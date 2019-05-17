use std::collections::HashMap;

use openssl::ssl;
use std::sync::RwLock;

pub struct SessionStore {
    sessions: RwLock<HashMap<Vec<u8>, ssl::SslSession>>,
}

impl SessionStore {
    pub fn new() -> Self {
        let sessions = RwLock::new(HashMap::new());
        Self { sessions }
    }

    pub fn insert(&self, _: &mut ssl::SslRef, session: ssl::SslSession) {
        let mut lock = self.sessions.write().unwrap();
        lock.insert(session.id().to_vec(), session);
    }
}
