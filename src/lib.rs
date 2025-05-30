use std::net;

use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, Nonce, OsRng},
    ChaCha20Poly1305, Key,
};
use kms::{
    kms_service_server::{KmsService, KmsServiceServer},
    Request, Response,
};
use tonic::transport::server::TcpConnectInfo;
use typenum::Unsigned;
use uuid::Uuid;

mod kms;

#[derive(Clone)]
pub enum KeySource {
    Kdf(Vec<u8>),
    Key(Key),
}

pub struct Unlocker {
    key: KeySource,
    allowed_ips: std::collections::HashSet<(net::IpAddr, Uuid)>,
}

impl Unlocker {
    pub fn new(
        allowed_ips: std::collections::HashSet<(net::IpAddr, Uuid)>,
        key: KeySource,
    ) -> KmsServiceServer<Self> {
        KmsServiceServer::new(Self { allowed_ips, key })
    }

    fn cipher_for_node(&self, node_uuid: &Uuid) -> Result<ChaCha20Poly1305, tonic::Status> {
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
                        Err(tonic::Status::invalid_argument("invalid request"))
                    }
                }
            }
        }
    }

    fn ensure_ip(&self, request: tonic::Request<Request>) -> Result<(Vec<u8>, Uuid), tonic::Status> {
        let connection_info = request.extensions().get::<TcpConnectInfo>().unwrap();
        let remote_addr = connection_info.remote_addr.unwrap().ip();
        let uuid = {
            let uuid = &request.get_ref().node_uuid;
            Uuid::parse_str(uuid).expect("valid uuid")
        };
        if !self.allowed_ips.is_empty() && !self.allowed_ips.contains(&(remote_addr, uuid)) {
            log::debug!(node_uuid:display = request.get_ref().node_uuid, ip:display = connection_info.remote_addr.unwrap(); "unallowed ip");
            Err(tonic::Status::permission_denied("invalid source IP"))
        } else {
            Ok((request.into_inner().data, uuid))
        }
    }
}

#[tonic::async_trait]
impl KmsService for Unlocker {
    async fn seal(
        &self,
        request: tonic::Request<Request>,
    ) -> Result<tonic::Response<Response>, tonic::Status> {
        let (request_data, node_uuid) = self.ensure_ip(request)?;

        log::debug!(node_uuid:%; "Seal request");

        let cipher = self.cipher_for_node(&node_uuid)?;

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
        let (request_data, node_uuid) = self.ensure_ip(request)?;

        log::debug!(node_uuid:%; "Unseal request");

        let cipher = self.cipher_for_node(&node_uuid)?;

        let (nonce, ciphertext) = {
            let nonce_size = <ChaCha20Poly1305 as AeadCore>::NonceSize::to_usize();
            match request_data.split_at_checked(nonce_size) {
                Some((raw_nonce, ciphertext)) => {
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
