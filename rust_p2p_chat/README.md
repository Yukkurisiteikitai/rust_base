
# usage
1. `cargo build`


2. boot
[User1]
./target/debug/rust_p2p_chat listen --addr 127.0.0.1:8080


[User2]
./target/debug/rust_p2p_chat connect wss://127.0.0.1:8080