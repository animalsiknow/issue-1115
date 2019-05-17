use openssl::ssl;

pub struct ContextStore {
    default_context: ssl::SslContext,
}

impl ContextStore {
    pub fn new(default_context: ssl::SslContext) -> Self {
        Self { default_context }
    }

    pub fn get_context(&self) -> ssl::SslContext {
        self.default_context.clone()
    }
}
