//! This is an example to show how to modify ClientHello to resist
//! TLS fingerprinting techniques. Expect JA3 hash = cd08e31494f9531f560d64c695473da9

use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use ja_tools::builder::JAOverrideBuilder;
use rustls::client::client_hello::CompressCertificateOptions;
use rustls::internal::msgs::enums::ExtensionType;
use rustls::internal::msgs::handshake::{ClientExtension, ProtocolName};
use rustls::CipherSuite::*;
use rustls::{ProtocolVersion, RootCertStore, SignatureScheme};

fn main() {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.alpn_protocols = vec!["http/1.1".as_bytes().to_vec()];
    let overrider = {
        // chrome 102
        let ja3_full = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0";
        // chrome 120
        let ja3_full = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,51-10-5-43-65281-35-16-11-13-23-17513-27-18-45-0-65037,29-23-24,0";
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
        builder
            .unknown_extensions
            .insert(65037, ja_tools::extensions::grease_ech());
        builder.with_ja3_full(ja3_full).unwrap()
    };

    rustls::client::danger::DangerousClientConfig { cfg: &mut config }
        .set_hello_override(Arc::new(overrider));

    let server_name = "tls.peet.ws".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect("tls.peet.ws:443").unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        concat!(
            "GET /api/all HTTP/1.1\r\n",
            "Host: tls.peet.ws\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}
