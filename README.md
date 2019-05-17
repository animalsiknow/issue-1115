# Issue 1115

This repository is a smallish application that demonstrate the issue explained in [issue 1115 of `rust-openssl`](https://github.com/sfackler/rust-openssl/issues/1115). You can run it like this.

    openssl req -x509 -newkey rsa:4096 -nodes -keyout private_key.pem -out certificate.pem -days 365
    cargo run
    
Then, in another terminal,

    openssl s_client -connect localhost:8080 -servername example.com
