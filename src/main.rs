use std::net::{SocketAddr, TcpListener, Ipv4Addr};
use std::sync::Arc;

use openssl::{pkey, x509};

use crate::builder::ContextBuilder;
use crate::context::ContextStore;
use crate::session::SessionStore;

mod builder;
mod context;
mod session;

const CERTIFICATE: &[u8] = include_bytes!("certificate.pem");
const PRIVATE_KEY: &[u8] = include_bytes!("private_key.pem");

pub struct Certificate {
    pub certificate: x509::X509,
    pub private_key: pkey::PKey<pkey::Private>,
}

impl Certificate {
    pub fn new(certificate: x509::X509, private_key: pkey::PKey<pkey::Private>) -> Self {
        Self {
            certificate,
            private_key,
        }
    }
}

fn main() {
    let certificate = {
        let mut certificates = x509::X509::stack_from_pem(CERTIFICATE).unwrap();
        assert_eq!(certificates.len(), 1);
        certificates.pop().unwrap()
    };
    let private_key = pkey::PKey::private_key_from_pem(PRIVATE_KEY).unwrap();
    let default_certificate = Certificate::new(certificate, private_key);

    let session_store = Arc::new(SessionStore::new());
    let default_context = {
        let mut builder = ContextBuilder::new_context_builder(&session_store).unwrap();
        builder.add_certificate(&default_certificate).unwrap();
        builder.build()
    };

    let context_store = Arc::new(ContextStore::new(default_context));
    let acceptor = {
        let mut builder = ContextBuilder::new_acceptor_builder(context_store, &session_store).unwrap();
        builder.add_certificate(&default_certificate).unwrap();
        builder.build()
    };

    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8080);
    let listener = TcpListener::bind(addr).unwrap();
    let (tcp_stream, _) = listener.accept().unwrap();
    acceptor.accept(tcp_stream).unwrap();
}
