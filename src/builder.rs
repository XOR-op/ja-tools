use crate::JAOverride;
use rustls::client::client_hello::CompressCertificateOptions;
use rustls::internal::msgs::enums::{ECPointFormat, ExtensionType, PSKKeyExchangeMode};
use rustls::internal::msgs::handshake::{ClientExtension, ClientSessionTicket, ProtocolName};
use rustls::{CipherSuite, NamedGroup, ProtocolVersion, SignatureScheme};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};

pub enum ExtensionChunk {
    Grease,
    Sni,
    KeyShare,
    GreasedNameGroups(Vec<NamedGroup>),
    GreasedTLSVersion(Vec<ProtocolVersion>),
    Extension(ClientExtension),
}

#[derive(Debug, Clone, Copy)]
pub enum FailReason<'a> {
    Part,
    CipherSuite(&'a str),
    NamedGroup(&'a str),
    ExtensionType(&'a str),
    MissingTLSVersion,
    MissingALPN,
    MissingSignatureAlgorithms,
    MissingCompressCertificate,
}

impl<'a> Display for FailReason<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Default)]
pub struct JAOverrideBuilder {
    pub tls_versions: Option<Vec<ProtocolVersion>>,
    pub alpn: Option<Vec<ProtocolName>>,
    pub signature_algorithms: Option<Vec<SignatureScheme>>,
    pub compress_certificate: Option<CompressCertificateOptions>,
    // empirical
    pub grease: bool,
    pub unknown_extensions: HashMap<u16, ClientExtension>,
    pub shuffle_extension: bool,
}

impl JAOverrideBuilder {
    pub fn with_ja3_full<'a>(&self, ja3: &'a str) -> Result<JAOverride, FailReason<'a>> {
        let parts: Vec<&str> = ja3.split(',').collect();
        if parts.len() != 5 {
            return Err(FailReason::Part);
        }
        let cipher_suites = {
            let mut suites = Vec::new();
            for suite in parts[1].split('-') {
                suites.push(CipherSuite::from(
                    suite
                        .parse::<u16>()
                        .map_err(|_| FailReason::CipherSuite(suite))?,
                ));
            }
            suites
        };
        let named_groups = {
            let mut groups = Vec::new();
            for group in parts[3].split('-') {
                groups.push(NamedGroup::from(
                    group
                        .parse::<u16>()
                        .map_err(|_| FailReason::NamedGroup(group))?,
                ));
            }
            groups
        };
        let extensions = {
            let mut exts = if self.grease {
                vec![ExtensionChunk::Grease]
            } else {
                Vec::new()
            };
            for ext in parts[2].split('-') {
                exts.push(
                    match ExtensionType::from(
                        ext.parse::<u16>()
                            .map_err(|_| FailReason::ExtensionType(ext))?,
                    ) {
                        ExtensionType::EllipticCurves => {
                            if self.grease {
                                ExtensionChunk::GreasedNameGroups(named_groups.clone())
                            } else {
                                ExtensionChunk::Extension(ClientExtension::NamedGroups(
                                    named_groups.clone(),
                                ))
                            }
                        }
                        ExtensionType::SupportedVersions => {
                            if self.grease {
                                ExtensionChunk::GreasedTLSVersion(
                                    self.tls_versions
                                        .clone()
                                        .ok_or(FailReason::MissingTLSVersion)?,
                                )
                            } else {
                                ExtensionChunk::Extension(ClientExtension::SupportedVersions(
                                    self.tls_versions
                                        .clone()
                                        .ok_or(FailReason::MissingTLSVersion)?,
                                ))
                            }
                        }
                        ExtensionType::ALProtocolNegotiation => {
                            ExtensionChunk::Extension(ClientExtension::Protocols(
                                self.alpn.clone().ok_or(FailReason::MissingALPN)?,
                            ))
                        }
                        ExtensionType::SignatureAlgorithms => {
                            ExtensionChunk::Extension(ClientExtension::SignatureAlgorithms(
                                self.signature_algorithms
                                    .clone()
                                    .ok_or(FailReason::MissingSignatureAlgorithms)?,
                            ))
                        }
                        ExtensionType::Unknown(27) => {
                            ExtensionChunk::Extension(ClientExtension::compress_certificate(&[
                                self.compress_certificate
                                    .ok_or(FailReason::MissingCompressCertificate)?,
                            ]))
                        }
                        oth => {
                            if let Some(exten) = convert_extension(oth) {
                                exten
                            } else {
                                ExtensionChunk::Extension(
                                    self.unknown_extensions
                                        .get(&u16::from(oth))
                                        .ok_or(FailReason::ExtensionType(ext))?
                                        .clone(),
                                )
                            }
                        }
                    },
                );
            }
            if self.grease {
                if let Some(ExtensionChunk::Extension(e)) = exts.last() {
                    if e.get_ext_type() == ExtensionType::Padding {
                        exts.insert(exts.len() - 1, ExtensionChunk::Grease);
                    } else {
                        exts.push(ExtensionChunk::Grease);
                    }
                } else {
                    exts.push(ExtensionChunk::Grease);
                }
            }
            exts
        };
        Ok(JAOverride {
            cipher_suites,
            extensions,
            shuffle_extension: self.shuffle_extension,
        })
    }
}

fn convert_extension(ext_ty: ExtensionType) -> Option<ExtensionChunk> {
    match ext_ty {
        ExtensionType::ServerName => Some(ExtensionChunk::Sni),
        ExtensionType::KeyShare => Some(ExtensionChunk::KeyShare),
        ExtensionType::ExtendedMasterSecret => Some(ExtensionChunk::Extension(
            ClientExtension::ExtendedMasterSecretRequest,
        )),
        ExtensionType::RenegotiationInfo => Some(ExtensionChunk::Extension(
            ClientExtension::renegotiation_info(),
        )),
        ExtensionType::StatusRequest => {
            Some(ExtensionChunk::Extension(ClientExtension::status_request()))
        }
        ExtensionType::SCT => Some(ExtensionChunk::Extension(
            ClientExtension::signed_certificate_timestamp(),
        )),
        ExtensionType::Padding => Some(ExtensionChunk::Extension(ClientExtension::padding(vec![]))),
        ExtensionType::PSKKeyExchangeModes => Some(ExtensionChunk::Extension(
            ClientExtension::PresharedKeyModes(vec![PSKKeyExchangeMode::PSK_DHE_KE]),
        )),
        ExtensionType::SessionTicket => Some(ExtensionChunk::Extension(
            ClientExtension::SessionTicket(ClientSessionTicket::Request),
        )),
        ExtensionType::ECPointFormats => Some(ExtensionChunk::Extension(
            ClientExtension::EcPointFormats(vec![ECPointFormat::Uncompressed]),
        )),
        _ => None,
    }
}

impl JAOverrideBuilder {
    pub fn with_grease(&mut self, grease: bool) -> &mut Self {
        self.grease = grease;
        self
    }

    pub fn with_shuffle_extension(&mut self, shuffle_extension: bool) -> &mut Self {
        self.shuffle_extension = shuffle_extension;
        self
    }

    pub fn with_tls_versions(&mut self, tls_versions: Vec<ProtocolVersion>) -> &mut Self {
        self.tls_versions = Some(tls_versions);
        self
    }

    pub fn with_alpn(&mut self, alpn: Vec<ProtocolName>) -> &mut Self {
        self.alpn = Some(alpn);
        self
    }

    pub fn with_signature_algorithms(
        &mut self,
        signature_algorithms: Vec<SignatureScheme>,
    ) -> &mut Self {
        self.signature_algorithms = Some(signature_algorithms);
        self
    }

    pub fn with_compress_certificate(
        &mut self,
        compress_certificate: CompressCertificateOptions,
    ) -> &mut Self {
        self.compress_certificate = Some(compress_certificate);
        self
    }
}

mod test {
    use super::*;

    #[test]
    fn test_ja3_full() {
        let ja3_full = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0";
        let mut builder = JAOverrideBuilder::default();
        builder
            .with_grease(true)
            .with_signature_algorithms(vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PKCS1_SHA512,
            ])
            .with_tls_versions(vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2])
            .with_alpn(vec![ProtocolName::from("http/1.1".as_bytes().to_vec())])
            .with_compress_certificate(CompressCertificateOptions::Brotli);
        builder.unknown_extensions.insert(
            17513,
            ClientExtension::unknown(ExtensionType::Unknown(17513), [0x0, 0x3, 0x2, 68, 32]),
        );
        let overrider = builder.with_ja3_full(ja3_full).unwrap();
        #[cfg(feature = "ja3")]
        {
            assert_eq!(overrider.ja3_full(), ja3_full);
            assert_eq!(overrider.ja3_hash(), "cd08e31494f9531f560d64c695473da9");
        }
        #[cfg(feature = "ja4")]
        assert_eq!(overrider.ja4_hash(), "t13d1514h1_8daaf6152771_e5627efa2ab1");
    }
}
