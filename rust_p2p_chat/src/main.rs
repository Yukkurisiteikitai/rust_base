use clap::{Parser, Subcommand};
use futures_util::{stream::StreamExt, SinkExt};
use rcgen::generate_simple_self_signed;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{stdin, AsyncBufReadExt, BufReader};
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
        #[arg(help = "接続先のサーバーアドレス (例: wss://127.0.0.1:8080)")]
        uri: String,
    },
}

// グローバルIPアドレスを取得する関数
async fn get_global_ip() -> Result<String, Box<dyn std::error::Error>> {
    // 複数のサービスを試行して、より確実にIPを取得
    let services = [
        "https://api.ipify.org",
        "https://httpbin.org/ip",
        "https://icanhazip.com",
    ];

    for service in &services {
        match try_get_ip_from_service(service).await {
            Ok(ip) => return Ok(ip),
            Err(e) => {
                eprintln!("{}からのIP取得に失敗: {}", service, e);
                continue;
            }
        }
    }

    Err("すべてのIPサービスからの取得に失敗しました".into())
}

async fn try_get_ip_from_service(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    
    let response = client.get(url).send().await?;
    let text = response.text().await?;
    
    // サービスによってレスポンス形式が異なるため、IPアドレスを抽出
    let ip = if url.contains("httpbin.org") {
        // httpbin.orgはJSON形式: {"origin": "x.x.x.x"}
        let json: serde_json::Value = serde_json::from_str(&text)?;
        json["origin"].as_str().unwrap_or("").to_string()
    } else {
        // その他のサービスはプレーンテキスト
        text.trim().to_string()
    };
    
    // IPアドレスの簡単な検証
    if ip.is_empty() || !ip.chars().any(|c| c.is_ascii_digit()) {
        return Err("無効なIPアドレス形式".into());
    }
    
    Ok(ip)
}

// ローカルIPアドレスを取得する関数
async fn get_local_ip() -> Result<String, Box<dyn std::error::Error>> {
    use std::net::UdpSocket;
    
    // ダミーの外部アドレスに接続して、使用されるローカルIPを取得
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    let local_addr = socket.local_addr()?;
    Ok(local_addr.ip().to_string())
}

// サーバー側の処理
async fn run_server(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    println!("サーバーを起動します: {}", addr);
    
    // ローカルIPアドレスを取得して表示
    if let Ok(local_ip) = get_local_ip().await {
        println!("ローカルIPアドレス: {}", local_ip);
        println!("ローカルネットワーク内からの接続用URL: wss://{}:{}", local_ip, addr.port());
    }
    
    // グローバルIPアドレスを取得して表示
    println!("グローバルIPアドレスを取得中...");
    match get_global_ip().await {
        Ok(global_ip) => {
            println!("グローバルIPアドレス: {}", global_ip);
            let port = addr.port();
            println!("外部からの接続用URL: wss://{}:{}", global_ip, port);
            println!("注意: 以下の設定が必要です:");
            println!("  1. Windowsファイアウォールでポート{}を開放", port);
            println!("  2. ルーターでポートフォワーディング設定 (外部{}→内部{}:{})", port, 
                    get_local_ip().await.unwrap_or_else(|_| "LOCAL_IP".to_string()), port);
            println!("  3. ISPがポート{}をブロックしていないことを確認", port);
        }
        Err(e) => {
            eprintln!("グローバルIPアドレスの取得に失敗しました: {}", e);
            println!("ローカルアドレスでのみ接続を受け付けます");
        }
    }

    // 1. 自己署名証明書の生成
    let cert = generate_simple_self_signed(vec!["localhost".into()])?;
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let cert_chain = vec![cert.cert.der().clone()];

    // 2. TLSサーバー設定
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
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
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    
    // サーバー証明書の検証をスキップするカスタム検証ロジック
    config.dangerous().set_certificate_verifier(Arc::new(NoopServerCertVerifier));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let connector = TlsConnector::from(Arc::new(config));
    let url = url::Url::parse(uri)?;
    let host = url.host_str().ok_or("URIにホスト名がありません")?;
    let port = url.port().unwrap_or(8080);

    // 2. TCP接続とTLSハンドシェイク
    let addr = format!("{}:{}", host, port);
    let stream = TcpStream::connect(&addr).await?;
    let domain = rustls::pki_types::ServerName::try_from(host)?.to_owned();
    let tls_stream = connector.connect(domain, stream).await?;

    // 3. WebSocketハンドシェイク
    let (ws_stream, _) = tokio_tungstenite::client_async(uri, tls_stream).await?;
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
        // すべての一般的な署名スキームをサポート
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

// 接続後のメッセージ送受信をハンドルする共通関数
async fn handle_connection<S>(ws_stream: tokio_tungstenite::WebSocketStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    println!("チャットを開始します。メッセージを入力してEnterキーを押してください。");

    // WebSocketストリームを送信と受信に分割
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    let mut stdin = BufReader::new(stdin()).lines();

    loop {
        tokio::select! {
            // 標準入力からメッセージを読み取って送信
            line_result = stdin.next_line() => {
                match line_result {
                    Ok(Some(line)) => {
                        if line.trim().is_empty() {
                            continue;
                        }
                        if let Err(e) = ws_sender.send(tokio_tungstenite::tungstenite::Message::Text(line)).await {
                            println!("メッセージ送信エラー: {}", e);
                            break;
                        }
                    }
                    Ok(None) => {
                        println!("標準入力が閉じられました。");
                        break;
                    }
                    Err(e) => {
                        println!("標準入力読み取りエラー: {}", e);
                        break;
                    }
                }
            }
            // WebSocketからメッセージを受信して表示
            msg_result = ws_receiver.next() => {
                match msg_result {
                    Some(Ok(msg)) => {
                        match msg {
                            tokio_tungstenite::tungstenite::Message::Text(text) => {
                                println!("相手: {}", text);
                            }
                            tokio_tungstenite::tungstenite::Message::Close(close_frame) => {
                                if let Some(frame) = close_frame {
                                    println!("相手が接続を切断しました: {} - {}", frame.code, frame.reason);
                                } else {
                                    println!("相手が接続を切断しました。");
                                }
                                break;
                            }
                            tokio_tungstenite::tungstenite::Message::Ping(data) => {
                                if let Err(e) = ws_sender.send(tokio_tungstenite::tungstenite::Message::Pong(data)).await {
                                    println!("Pong送信エラー: {}", e);
                                    break;
                                }
                            }
                            _ => {
                                // その他のメッセージタイプは無視
                            }
                        }
                    }
                    Some(Err(e)) => {
                        println!("WebSocketエラー: {}", e);
                        break;
                    }
                    None => {
                        println!("WebSocket接続が閉じられました。");
                        break;
                    }
                }
            }
        }
    }

    println!("チャット終了。");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Rustlsの暗号化プロバイダーを初期化
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "暗号化プロバイダーの初期化に失敗しました")?;

    let cli = Cli::parse();

    match &cli.command {
        Commands::Listen { addr } => {
            if let Err(e) = run_server(*addr).await {
                eprintln!("サーバーエラー: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Connect { uri } => {
            if let Err(e) = run_client(uri).await {
                eprintln!("クライアントエラー: {}", e);
                std::process::exit(1);
            }
        }
    }

    Ok(())
}