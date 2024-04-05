use rustls::internal::msgs::enums::ExtensionType;
use rustls::internal::msgs::enums::HpkeAead::AES_128_GCM;
use rustls::internal::msgs::enums::HpkeKdf::HKDF_SHA256;
use rustls::internal::msgs::handshake::ClientExtension;

pub fn grease_ech() -> ClientExtension {
    let mut payload = Vec::with_capacity(200);
    // Outer Client Hello
    payload.push(0);
    payload.extend_from_slice(&u16::from(HKDF_SHA256).to_be_bytes());
    payload.extend_from_slice(&u16::from(AES_128_GCM).to_be_bytes());
    // Config Id
    payload.push(rand::random());
    // Enc Length+Payload
    payload.extend_from_slice(&32u16.to_be_bytes());
    for _ in 0..32 {
        payload.push(rand::random());
    }
    // Payload Length+Payload
    payload.extend_from_slice(&144u16.to_be_bytes());
    for _ in 0..144 {
        payload.push(rand::random());
    }
    ClientExtension::unknown(ExtensionType::Unknown(65037), payload)
}
