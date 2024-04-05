pub mod builder;
pub mod extensions;
mod hash;

use rand::prelude::SliceRandom;
use rustls::internal::msgs::handshake::ClientExtension;
use rustls::{CipherSuite, NamedGroup, ProtocolVersion};
use std::fmt::Debug;

use crate::builder::{ExtensionChunk, JAOverrideBuilder};
pub use rustls as rustls_vendor;
use rustls::client::client_hello::ClientHelloOverride;
use rustls::internal::msgs::enums::ExtensionType;

pub struct JAOverride {
    pub(crate) cipher_suites: Vec<CipherSuite>,
    pub(crate) extensions: Vec<ExtensionChunk>,
    pub(crate) shuffle_extension: bool,
}

impl JAOverride {
    pub fn builder() -> JAOverrideBuilder {
        JAOverrideBuilder::default()
    }
}

impl Debug for JAOverride {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JAOverride").finish()
    }
}

impl ClientHelloOverride for JAOverride {
    fn override_cipher_suites(&self, _cipher_suites: Vec<CipherSuite>) -> Vec<CipherSuite> {
        self.cipher_suites.clone()
    }

    fn override_extensions(&self, extensions: Vec<ClientExtension>) -> Vec<ClientExtension> {
        let mut res = Vec::with_capacity(self.extensions.len());
        for ext in self.extensions.iter() {
            match ext {
                ExtensionChunk::Grease => {
                    res.push(ClientExtension::grease());
                }
                ExtensionChunk::Sni => {
                    if let Some(sni) = extensions
                        .iter()
                        .find(|ext| matches!(ext, ClientExtension::ServerName(_)))
                    {
                        res.push(sni.clone());
                    }
                }
                ExtensionChunk::KeyShare => {
                    if let Some(key_share) = extensions
                        .iter()
                        .find(|ext| matches!(ext, ClientExtension::KeyShare(_)))
                    {
                        res.push(key_share.clone());
                    }
                }
                ExtensionChunk::Extension(ext) => {
                    res.push(ext.clone());
                }
                ExtensionChunk::GreasedNameGroups(v) => {
                    let mut groups = Vec::with_capacity(v.len() + 1);
                    groups.push(NamedGroup::grease());
                    groups.extend(v.iter().cloned());
                    res.push(ClientExtension::NamedGroups(groups));
                }
                ExtensionChunk::GreasedTLSVersion(v) => {
                    let mut versions = Vec::with_capacity(v.len() + 1);
                    versions.push(ProtocolVersion::grease());
                    versions.extend(v.iter().cloned());
                    res.push(ClientExtension::SupportedVersions(versions));
                }
            }
        }
        if self.shuffle_extension {
            let first = self
                .extensions
                .iter()
                .enumerate()
                .position(|(_, chk)| !matches!(chk, ExtensionChunk::Grease));
            let last = self.extensions.iter().enumerate().rposition(|(_, chk)| {
                !matches!(chk, ExtensionChunk::Grease)
                    && if let ExtensionChunk::Extension(e) = chk {
                        e.get_ext_type() != ExtensionType::Padding
                    } else {
                        true
                    }
            });
            if let (Some(first), Some(last)) = (first, last) {
                res[first..=last].shuffle(&mut rand::thread_rng());
            }
        }
        res
    }
}
