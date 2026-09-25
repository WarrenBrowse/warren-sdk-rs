//! The engine's NAT-PMP server, in process, behind a credential authority that
//! requires a credential the way an exit enforcing warren-core doc 105 does.
//!
//! The server is the one exits run (`warrenguard-natpmp-server` over its stub
//! backend), so what the SDK's client sends is parsed, gated and allocated by
//! the real code; only the credential verdict is scripted here, because
//! verifying and spending an entitlement is the deployer's job, not the
//! engine's.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use warrenguard_natpmp_server::server::{CredentialAuthority, CredentialVerdict, Server};
use warrenguard_natpmp_server::stub_backend::StubBackend;

/// Records every credential presented and grants the first `grant_budget`
/// presentations. A request presenting nothing is refused (`NotAuthorized`).
struct RequireCredential {
    presented: Mutex<Vec<Vec<u8>>>,
    grant_budget: usize,
}

impl CredentialAuthority for RequireCredential {
    fn present<'a>(
        &'a self,
        _client_ip: Ipv4Addr,
        credential: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = CredentialVerdict> + Send + 'a>> {
        Box::pin(async move {
            let mut presented = self.presented.lock().expect("presented lock");
            presented.push(credential.to_vec());
            if presented.len() > self.grant_budget {
                CredentialVerdict::Refuse
            } else {
                CredentialVerdict::Grant
            }
        })
    }

    fn requires_credential(&self) -> bool {
        true
    }
}

/// A running engine NAT-PMP server on `127.0.0.1`, stopped on drop.
pub struct EngineNatPmp {
    addr: SocketAddr,
    backend: Arc<StubBackend>,
    authority: Arc<RequireCredential>,
    task: tokio::task::JoinHandle<()>,
}

impl EngineNatPmp {
    /// A server that grants every presented credential.
    ///
    /// # Panics
    ///
    /// When the loopback socket cannot be bound (a broken test host).
    pub async fn spawn() -> Self {
        Self::spawn_granting(usize::MAX).await
    }

    /// A server that grants the first `grant_budget` presentations and
    /// refuses every later one, as an exit refuses an entitlement it will not
    /// spend.
    ///
    /// # Panics
    ///
    /// When the loopback socket cannot be bound (a broken test host).
    pub async fn spawn_granting(grant_budget: usize) -> Self {
        let backend = Arc::new(StubBackend::new());
        let authority = Arc::new(RequireCredential {
            presented: Mutex::new(Vec::new()),
            grant_budget,
        });
        let server = Server::bind_with_filter(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            Arc::clone(&backend),
            Ipv4Addr::new(198, 51, 100, 1),
            // Loopback is outside the tunnel pool the default filter admits.
            Arc::new(|_| true),
        )
        .await
        .expect("bind the engine nat-pmp server")
        .with_credential_authority(Arc::clone(&authority) as Arc<dyn CredentialAuthority>);
        let addr = server.local_addr().expect("server address");
        let task = tokio::spawn(async move {
            let _ = server.run().await;
        });
        Self {
            addr,
            backend,
            authority,
            task,
        }
    }

    /// Where the server listens.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Every credential presented so far, in arrival order.
    ///
    /// # Panics
    ///
    /// When the recording lock is poisoned.
    #[must_use]
    pub fn presented(&self) -> Vec<Vec<u8>> {
        self.authority
            .presented
            .lock()
            .expect("presented lock")
            .clone()
    }

    /// Live mappings the server's allocator holds.
    #[must_use]
    pub fn active_mappings(&self) -> usize {
        self.backend.allocator().active_count()
    }
}

impl Drop for EngineNatPmp {
    fn drop(&mut self) {
        self.task.abort();
    }
}
