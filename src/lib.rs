use std::{net, ops::Deref};

use argon2::Argon2;
use chacha20poly1305::{
    ChaCha20Poly1305, Key,
    aead::{Aead, AeadCore, KeyInit, Nonce, OsRng},
};
use kms::{
    Request, Response,
    kms_service_server::{KmsService, KmsServiceServer},
};
use tokio::sync::{broadcast, watch};
use tonic::transport::server::TcpConnectInfo;
use typenum::Unsigned;
pub use types::ClusterNodes;
use types::{Attempt, AttemptKind, AttemptResponse};
use uuid::Uuid;

mod kms;
pub mod sync;
pub mod telegram;
mod types;

#[derive(Clone)]
pub enum KeySource {
    Kdf(Vec<u8>),
    Key(Key),
}

pub struct Unlocker {
    key: KeySource,
    allowed_ips: watch::Receiver<std::collections::HashSet<(net::IpAddr, Uuid)>>,
    notify_attempt: broadcast::Sender<Attempt>,
}

impl Unlocker {
    pub fn new(
        key: KeySource,
        allowed_ips: watch::Receiver<std::collections::HashSet<(net::IpAddr, Uuid)>>,
        notify_attempt: broadcast::Sender<Attempt>,
    ) -> KmsServiceServer<Self> {
        KmsServiceServer::new(Self {
            key,
            allowed_ips,
            notify_attempt,
        })
    }

    fn cipher_for_node(&self, node_uuid: &Uuid) -> Result<ChaCha20Poly1305, tonic::Code> {
        match &self.key {
            KeySource::Key(key) => Ok(ChaCha20Poly1305::new(key)),
            KeySource::Kdf(passphrase) => {
                let mut key = Key::default();
                match Argon2::default().hash_password_into(
                    passphrase.as_ref(),
                    node_uuid.as_ref(),
                    &mut key,
                ) {
                    Ok(()) => Ok(ChaCha20Poly1305::new(&key)),
                    Err(err) => {
                        log::error!(err:err, node_uuid:display = &node_uuid; "couldn't get cipher");
                        Err(tonic::Code::InvalidArgument)
                    }
                }
            }
        }
    }

    async fn ensure_permission(
        &self,
        kind: AttemptKind,
        request: tonic::Request<Request>,
    ) -> Result<(Vec<u8>, Uuid), tonic::Status> {
        let connection_info = request.extensions().get::<TcpConnectInfo>().unwrap();
        let remote_addr = connection_info.remote_addr.unwrap().ip();
        let uuid = {
            let uuid = &request.get_ref().node_uuid;
            Uuid::parse_str(uuid).expect("valid uuid")
        };
        let tonic_resp = if !self.allowed_ips.borrow().contains(&(remote_addr, uuid)) {
            log::debug!(node_uuid:% = request.get_ref().node_uuid, allowed_ips:? = self.allowed_ips.borrow().deref(), remote_addr:%; "unknown ip");
            Err(tonic::Status::permission_denied("invalid source IP"))
        } else {
            Ok((request.into_inner().data, uuid))
        };

        let _ = self.notify_attempt.clone().send(Attempt {
            addr: remote_addr,
            node: uuid,
            kind,
            resp: match tonic_resp {
                Ok(_) => AttemptResponse::Allow,
                Err(_) => AttemptResponse::Block,
            },
        });
        tonic_resp
    }
}

#[tonic::async_trait]
impl KmsService for Unlocker {
    async fn seal(
        &self,
        request: tonic::Request<Request>,
    ) -> Result<tonic::Response<Response>, tonic::Status> {
        let (request_data, node_uuid) = self.ensure_permission(AttemptKind::Seal, request).await?;

        log::debug!(node_uuid:%; "Seal request");

        let cipher = self
            .cipher_for_node(&node_uuid)
            .map_err(|e| tonic::Status::new(e, "invalid request"))?;

        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, request_data.as_ref())
            .map_err(|err| {
                log::error!(err:err, node_uuid:display; "couldn't encrypt");
                tonic::Status::invalid_argument("invalid request")
            })?;

        let mut sealed = nonce.to_vec();
        sealed.extend(ciphertext);
        log::info!(node_uuid:%; "Seal granted");
        Ok(tonic::Response::new(Response { data: sealed }))
    }

    async fn unseal(
        &self,
        request: tonic::Request<Request>,
    ) -> Result<tonic::Response<Response>, tonic::Status> {
        let (request_data, node_uuid) =
            self.ensure_permission(AttemptKind::Unseal, request).await?;

        log::debug!(node_uuid:%; "Unseal request");

        let cipher = self
            .cipher_for_node(&node_uuid)
            .map_err(|e| tonic::Status::new(e, "invalid request"))?;

        let (nonce, ciphertext) = {
            let nonce_size = <ChaCha20Poly1305 as AeadCore>::NonceSize::to_usize();
            match request_data.split_at_checked(nonce_size) {
                Some((raw_nonce, ciphertext)) =>
                {
                    #[expect(deprecated, reason = "generic-array insanity")]
                    Ok((Nonce::<ChaCha20Poly1305>::from_slice(raw_nonce), ciphertext))
                }
                None => {
                    log::error!(node_uuid:%; "request data too short");
                    Err(tonic::Status::invalid_argument("invalid request"))
                }
            }
        }?;

        match cipher.decrypt(nonce, ciphertext) {
            Ok(plaintext) => {
                log::info!(node_uuid:%; "Unseal granted");
                Ok(tonic::Response::new(Response { data: plaintext }))
            }
            Err(err) => {
                log::error!(err:err, node_uuid:display = &node_uuid; "couldn't decrypt");
                Err(tonic::Status::invalid_argument("invalid request"))
            }
        }
    }
}
