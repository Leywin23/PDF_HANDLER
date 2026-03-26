use cms::{
    builder::{SignedDataBuilder, SignerInfoBuilder},
    cert::CertificateChoices,
    signed_data::{EncapsulatedContentInfo, SignerIdentifier},
};
use const_oid::{
    db::rfc5911::ID_DATA,
    db::rfc5912::ID_SHA_256,
};
use p12::PFX;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

struct SigningIdentity {
    key: RsaPrivateKey,
    cert: Certificate,
    chain: Vec<Certificate>,
}

pub fn pkcs7_detached_from_pfx(
    pfx: &[u8],
    password: &str,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let identity = extract_identity_from_pfx(pfx, password)?;

    let digest = Sha256::digest(data);

    let signer = SigningKey::<Sha256>::new(identity.key);

    let econtent = EncapsulatedContentInfo {
        econtent_type: ID_DATA,
        econtent: None,
    };

    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: ID_SHA_256,
        parameters: None,
    };

    let sid = SignerIdentifier::IssuerAndSerialNumber(
        cms::cert::IssuerAndSerialNumber {
            issuer: identity.cert.tbs_certificate.issuer.clone(),
            serial_number: identity.cert.tbs_certificate.serial_number.clone(),
        }
    );

    let signer_info = SignerInfoBuilder::new(
        &signer,
        sid,
        digest_algorithm.clone(),
        &econtent,
        Some(&digest),
    )
    .map_err(|e| format!("SignerInfoBuilder::new failed: {e}"))?;

    let mut signed_data = SignedDataBuilder::new(&econtent);

    signed_data
        .add_digest_algorithm(digest_algorithm)
        .map_err(|e| format!("add_digest_algorithm failed: {e}"))?;

    signed_data
        .add_certificate(CertificateChoices::Certificate(identity.cert.clone()))
        .map_err(|e| format!("add_certificate leaf failed: {e}"))?;

    for cert in identity.chain.iter().cloned() {
        signed_data
            .add_certificate(CertificateChoices::Certificate(cert))
            .map_err(|e| format!("add_certificate chain failed: {e}"))?;
    }

    signed_data
        .add_signer_info(signer_info)
        .map_err(|e| format!("add_signer_info failed: {e}"))?;

    let content_info = signed_data
        .build()
        .map_err(|e| format!("SignedDataBuilder::build failed: {e}"))?;

    content_info
        .to_der()
        .map_err(|e| format!("CMS to_der failed: {e}"))
}

fn extract_identity_from_pfx(pfx_bytes: &[u8], password: &str) -> Result<SigningIdentity, String> {
    let pfx = PFX::parse(pfx_bytes)
        .map_err(|e| format!("PFX parse failed: {e:?}"))?;

    if !pfx.verify_mac(password) {
        return Err("PFX MAC verification failed. Złe hasło albo uszkodzony plik .p12/.pfx".to_string());
    }

    let key_bags = pfx
        .key_bags(password)
        .map_err(|e| format!("PFX key_bags failed: {e:?}"))?;

    let cert_bags = pfx
        .cert_x509_bags(password)
        .map_err(|e| format!("PFX cert_x509_bags failed: {e:?}"))?;

    if key_bags.is_empty() {
        return Err("PFX does not contain a private key".to_string());
    }

    if cert_bags.is_empty() {
        return Err("PFX does not contain any X.509 certificate".to_string());
    }

    let key = RsaPrivateKey::from_pkcs8_der(&key_bags[0])
        .map_err(|e| format!("RSA private key decode failed: {e}"))?;

    let cert = Certificate::from_der(&cert_bags[0])
        .map_err(|e| format!("Leaf certificate decode failed: {e}"))?;

    let mut chain = Vec::new();
    for der in cert_bags.iter().skip(1) {
        let parsed = Certificate::from_der(der)
            .map_err(|e| format!("Chain certificate decode failed: {e}"))?;
        chain.push(parsed);
    }

    Ok(SigningIdentity { key, cert, chain })
}