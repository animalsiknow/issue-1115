use std::sync::Arc;

use failure::Error;
use openssl::ssl;

use crate::Certificate;
use crate::context::ContextStore;
use crate::session::SessionStore;

pub struct ContextBuilder<T: ContextBuilderLike> {
    inner: T,
}

impl ContextBuilder<ssl::SslContextBuilder> {
    pub fn new_context_builder(session_store: &Arc<SessionStore>) -> Result<Self, Error> {
        Self::new(
            ssl::SslContextBuilder::new(ssl::SslMethod::tls())?,
            session_store,
        )
    }
}

impl ContextBuilder<ssl::SslAcceptorBuilder> {
    pub fn new_acceptor_builder(
        context_store: Arc<ContextStore>,
        session_store: &Arc<SessionStore>,
    ) -> Result<Self, Error> {
        let mut builder = ssl::SslAcceptor::mozilla_intermediate(ssl::SslMethod::tls())?;

        builder.set_servername_callback(move |ssl_ref, _ssl_alert| {
            ssl_ref.set_ssl_context(context_store.get_context().as_ref()).unwrap();
            Ok(())
        });

        Self::new(builder, session_store)
    }
}

impl<T: ContextBuilderLike> ContextBuilder<T> {
    fn new(mut inner: T, session_store: &Arc<SessionStore>) -> Result<Self, Error> {
        let builder = inner.as_ssl_context_builder();

        let mode = ssl::SslSessionCacheMode::SERVER | ssl::SslSessionCacheMode::NO_INTERNAL;
        builder.set_session_cache_mode(mode);

        // builder.set_new_session_callback(build_new_session_callback(session_store));
        let session_store_0 = Arc::clone(session_store);
        builder.set_new_session_callback(move |ssl, session| session_store_0.insert(ssl, session));

        builder.clear_options(ssl::SslOptions::NO_TLSV1_3);

        Ok(Self {
            inner,
        })
    }

    pub fn add_certificate(&mut self, certificate: &Certificate) -> Result<(), Error> {
        let builder = self.inner.as_ssl_context_builder();

        builder.set_certificate(certificate.certificate.as_ref())?;
        builder.set_private_key(certificate.private_key.as_ref())?;

        Ok(())
    }

    pub fn build(self) -> T::Context {
        self.inner.build()
    }
}

fn build_new_session_callback(
    session_store: &Arc<SessionStore>,
) -> impl Fn(&mut ssl::SslRef, ssl::SslSession) {
    let session_store = Arc::clone(session_store);
    move |ssl, session| session_store.insert(ssl, session)
}

pub trait ContextBuilderLike {
    type Context;

    fn as_ssl_context_builder(&mut self) -> &mut ssl::SslContextBuilder;

    fn build(self) -> Self::Context;
}

impl ContextBuilderLike for ssl::SslContextBuilder {
    type Context = ssl::SslContext;

    fn as_ssl_context_builder(&mut self) -> &mut ssl::SslContextBuilder {
        self
    }

    fn build(self) -> Self::Context {
        self.build()
    }
}

impl ContextBuilderLike for ssl::SslAcceptorBuilder {
    type Context = ssl::SslAcceptor;

    fn as_ssl_context_builder(&mut self) -> &mut ssl::SslContextBuilder {
        &mut *self
    }

    fn build(self) -> Self::Context {
        self.build()
    }
}
