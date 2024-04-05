use crate::builder::ExtensionChunk;
use crate::JAOverride;
use rustls::internal::msgs::enums::ExtensionType;
use rustls::internal::msgs::handshake::ClientExtension;
use rustls::ProtocolVersion;
use sha2::Digest;
use std::fmt::Write;

const TLS_GREASE_VALUES_INT: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

impl JAOverride {
    #[cfg(feature = "ja3")]
    pub fn ja3_full(&self) -> String {
        format!(
            "{},{},{},{},{}",
            771,
            self.cipher_suites
                .iter()
                .map(|c| u16::from(*c).to_string())
                .collect::<Vec<_>>()
                .join("-"),
            extension_to_vec(&self.extensions)
                .into_iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join("-"),
            self.extensions
                .iter()
                .filter_map(|e| match e {
                    ExtensionChunk::Extension(ClientExtension::NamedGroups(g)) => Some(g),
                    ExtensionChunk::GreasedNameGroups(g) => Some(g),
                    _ => None,
                })
                .next()
                .map(|e| e
                    .iter()
                    .map(|s| u16::from(*s).to_string())
                    .collect::<Vec<String>>()
                    .join("-"))
                .unwrap_or_default(),
            self.extensions
                .iter()
                .filter_map(|e| match e {
                    ExtensionChunk::Extension(ClientExtension::EcPointFormats(f)) => Some(f),
                    _ => None,
                })
                .next()
                .map(|e| e
                    .iter()
                    .map(|f| u8::from(*f).to_string())
                    .collect::<Vec<String>>()
                    .join("-"))
                .unwrap_or_default(),
        )
    }

    #[cfg(feature = "ja3")]
    pub fn ja3_hash(&self) -> String {
        format!("{:x}", md5::compute(self.ja3_full().as_bytes()))
    }

    #[cfg(feature = "ja4")]
    pub fn ja4_hash(&self) -> String {
        let tls_versions = self
            .extensions
            .iter()
            .filter_map(|e| match e {
                ExtensionChunk::GreasedTLSVersion(v) => Some(v),
                ExtensionChunk::Extension(ClientExtension::SupportedVersions(v)) => Some(v),
                _ => None,
            })
            .next()
            .map(|v| {
                v.first()
                    .map(|v| match *v {
                        ProtocolVersion::TLSv1_3 => "13",
                        _ => "12",
                    })
                    .unwrap_or("12")
            })
            .unwrap_or("12");
        let has_domain = self.extensions.iter().any(|e| {
            matches!(e, ExtensionChunk::Sni)
                || matches!(e, ExtensionChunk::Extension(ClientExtension::ServerName(_)))
        });
        let mut ciphers = self
            .cipher_suites
            .iter()
            .filter_map(|c| {
                if TLS_GREASE_VALUES_INT.contains(&u16::from(*c)) {
                    None
                } else {
                    Some(format!("{:04x}", u16::from(*c)))
                }
            })
            .collect::<Vec<String>>();
        // ignore SNI and ALPN
        let mut extensions = extension_to_vec(&self.extensions)
            .into_iter()
            .filter_map(|s| {
                if s != 0 && s != 0x10 {
                    Some(format!("{:04x}", s))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let signature = self
            .extensions
            .iter()
            .find_map(|e| match e {
                ExtensionChunk::Extension(ClientExtension::SignatureAlgorithms(s)) => Some(
                    s.iter()
                        .map(|s| format!("{:04x}", u16::from(*s)))
                        .collect::<Vec<String>>(),
                ),
                _ => None,
            })
            .unwrap_or_default();
        // sort for ja4
        ciphers.sort_unstable();
        extensions.sort_unstable();
        let part_b = {
            let bin = sha2::Sha256::new_with_prefix(ciphers.join(",")).finalize();
            bin[..6].iter().fold(String::new(), |mut output, b| {
                let _ = write!(&mut output, "{:02x}", b);
                output
            })
        };
        let part_c = {
            let mut hasher = sha2::Sha256::new_with_prefix(extensions.join(","));
            hasher.update(b"_");
            hasher.update(signature.join(","));
            let bin = hasher.finalize();
            bin[..6].iter().fold(String::new(), |mut output, b| {
                let _ = write!(&mut output, "{:02x}", b);
                output
            })
        };
        let alpn = self
            .extensions
            .iter()
            .filter_map(|e| match e {
                ExtensionChunk::Extension(ClientExtension::Protocols(p)) => Some(p),
                _ => None,
            })
            .next()
            .map(|p| {
                p.first()
                    .map(|n| {
                        if n.as_ref() == b"h2" {
                            "h2"
                        } else if n.as_ref() == b"http/1.1" {
                            "h1"
                        } else {
                            "00"
                        }
                    })
                    .unwrap_or("00")
            })
            .unwrap_or("00");
        format!(
            "t{}{}{}{}{}_{}_{}",
            tls_versions,
            if has_domain { "d" } else { "i" },
            ciphers.len(),
            extensions.len(),
            alpn,
            part_b,
            part_c
        )
    }
}

fn extension_to_vec(ext: &[ExtensionChunk]) -> Vec<u16> {
    ext.iter()
        .filter_map(|e| match e {
            ExtensionChunk::Grease => None,
            ExtensionChunk::Sni => Some(u16::from(ExtensionType::ServerName)),
            ExtensionChunk::KeyShare => Some(u16::from(ExtensionType::KeyShare)),
            ExtensionChunk::GreasedNameGroups(_) => Some(u16::from(ExtensionType::EllipticCurves)),
            ExtensionChunk::GreasedTLSVersion(_) => {
                Some(u16::from(ExtensionType::SupportedVersions))
            }
            ExtensionChunk::Extension(e) => Some(u16::from(e.get_ext_type())),
        })
        .collect::<Vec<u16>>()
}
