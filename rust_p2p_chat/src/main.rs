use clap::{Parser, Subcommand};
use futures_util::{stream::StreamExt, SinkExt};
use rcgen::generate_simple_self_signed;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{stdin, AsyncBufReadExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{self, pki_types::CertificateDer, ClientConfig, ServerConfig};
use tokio_rustls::TlsConnector;

// コマンドライン引数の定義
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// サーバーとして起動し、接続を待ち受けます
    Listen {
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        addr: SocketAddr,
    },
    /// 指定したサーバーにクライアントとして接続します
    Connect {
        #[arg(help = "接続先のサーバーアドレス (例: wss://123.45.67.89:8080)")]
        uri: String,
    },
}

// サーバー側の処理
async fn run_server(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    println!("サーバーを起動します: {}", addr);

    // 1. 自己署名証明書の生成
    let cert = generate_simple_self_signed(vec!["localhost".into()])?;
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let cert_chain = vec![cert.cert.der().clone()];

    // 2. TLSサーバー設定
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()]; // WebSocketはHTTP/1.1上でハンドシェイク
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    // 3. TCPリスナーの起動
    let listener = TcpListener::bind(&addr).await?;
    println!("接続待受中... Ctrl+Cで終了");

    // 4. 接続を受け付け、処理する
    let (stream, peer_addr) = listener.accept().await?;
    println!("クライアントが接続しました: {}", peer_addr);

    let tls_stream = tls_acceptor.accept(stream).await?;

    // 5. WebSocketハンドシェイク
    let ws_stream = tokio_tungstenite::accept_async(tls_stream).await?;
    println!("WebSocket接続が確立しました。");

    handle_connection(ws_stream).await;

    Ok(())
}

// クライアント側の処理
async fn run_client(uri: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("サーバーに接続します: {}", uri);

    // 1. TLSクライアント設定（サーバー証明書を検証しない）
    let root_cert_store = rustls::RootCertStore::empty();
    // config変数を可変にする
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    
    // サーバー証明書の検証をスキップするカスタム検証ロジック
    config.dangerous().set_certificate_verifier(Arc::new(NoopServerCertVerifier));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let connector = TlsConnector::from(Arc::new(config));
    let url = url::Url::parse(uri)?;
    let host = url.host_str().ok_or("URIにホスト名がありません")?;

    // 2. TCP接続とTLSハンドシェイク
    let stream = TcpStream::connect(url.socket_addrs(|| Some(8080))?[0]).await?;
    let domain = rustls::pki_types::ServerName::try_from(host)?.to_owned();
    let tls_stream = connector.connect(domain, stream).await?;

    // 3. WebSocketハンドシェイク
    let ws_stream = tokio_tungstenite::client_async(uri, tls_stream).await?;
    println!("WebSocket接続が確立しました。");

    handle_connection(ws_stream).await;

    Ok(())
}

// サーバー証明書を検証しないためのダミー構造体
#[derive(Debug)]
struct NoopServerCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoopServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::ALL_SUPPORTED_SCHEMES.to_vec()
    }
}


// 接続後のメッセージ送受信をハンドルする共通関数
async fn handle_connection<S>(ws_stream: tokio_tungstenite::WebSocketStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    println!("チャットを開始します。メッセージを入力してEnterキーを押してください。");

    let mut stdin = tokio::io::BufReader::new(stdin()).lines();

    loop {
        tokio::select! {
            // 標準入力からメッセージを読み取って送信
            Ok(Some(line)) = stdin.next_line() => {
                if ws_stream.send(tokio_tungstenite::tungstenite::Message::Text(line)).await.is_err() {
                    println!("接続が切れました。");
                    break;
                }
            }
            // WebSocketからメッセージを受信して表示
            Some(Ok(msg)) = ws_stream.next() => {
                match msg {
                    tokio_tungstenite::tungstenite::Message::Text(text) => {
                        println!("相手: {}", text);
                    }
                    tokio_tungstenite::tungstenite::Message::Close(_) => {
                        println!("相手が接続を切断しました。");
                        break;
                    }
                    _ => {}
                }
            }
            else => {
                break;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Listen { addr } => {
            run_server(*addr).await?;
        }
        Commands::Connect { uri } => {
            run_client(uri).await?;
        }
    }

    Ok(())
}