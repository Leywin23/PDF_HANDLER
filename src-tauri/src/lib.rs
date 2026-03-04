// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/

use windows::Win32::Security::Cryptography::*;
use windows::core::{PCWSTR, PSTR};

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
fn sign_pdf_pades(
    pdf_bytes: Vec<u8>,
    p12_bytes: Vec<u8>,
    password: String,
    reason: Option<String>,
    location: Option<String>,
    signing_time: Option<String>,
) -> Result<Vec<u8>, String> {
    println!(
        "sign_pdf_pades: pdf={} bytes, p12={} bytes, reason={:?}, location={:?}, signing_time={:?}",
        pdf_bytes.len(),
        p12_bytes.len(),
        reason,
        location,
        signing_time
    );

    // 1) Check: czy PFX da się zaimportować (hasło OK, format OK)
    pfx_can_import(&p12_bytes, &password)?;
    println!("PFX import OK");

    // 2) Check: czy Windows potrafi wygenerować CMS/PKCS#7 detached
    let sig_der = pkcs7_detached_from_pfx(&p12_bytes, &password, &pdf_bytes)?;
    println!("PKCS#7 detached signature len = {} bytes", sig_der.len());

    // Na razie zwracamy PDF bez zmian (PAdES w następnym kroku)
    Ok(pdf_bytes)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_geolocation::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![greet, sign_pdf_pades])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Sprawdza czy plik PFX/P12 można zaimportować do Windows CryptoAPI.
fn pfx_can_import(pfx: &[u8], password: &str) -> Result<(), String> {
    unsafe {
        let mut blob = CRYPT_INTEGER_BLOB {
            cbData: pfx.len() as u32,
            pbData: pfx.as_ptr() as *mut u8,
        };

        // password: UTF-16 + null terminator
        let mut pw: Vec<u16> = password.encode_utf16().collect();
        pw.push(0);

        let store = PFXImportCertStore(&mut blob, PCWSTR(pw.as_ptr()), CRYPT_USER_KEYSET)
            .map_err(|e| format!("PFXImportCertStore failed: {e:?}"))?;

        CertCloseStore(Some(store), 0)
            .map_err(|e| format!("CertCloseStore failed: {e:?}"))?;

        Ok(())
    }
}

/// Tworzy CMS/PKCS#7 detached signature z PFX (działa też z kluczem non-exportable).
fn pkcs7_detached_from_pfx(pfx: &[u8], password: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        // Import PFX do tymczasowego store
        let mut blob = CRYPT_INTEGER_BLOB {
            cbData: pfx.len() as u32,
            pbData: pfx.as_ptr() as *mut u8,
        };

        let mut pw: Vec<u16> = password.encode_utf16().collect();
        pw.push(0);

        let store = PFXImportCertStore(&mut blob, PCWSTR(pw.as_ptr()), CRYPT_USER_KEYSET)
            .map_err(|e| format!("PFXImportCertStore failed: {e:?}"))?;

        // Weź pierwszy cert z tego store
        let cert_ctx = CertEnumCertificatesInStore(store, None);
        if cert_ctx.is_null() {
            let _ = CertCloseStore(Some(store), 0);
            return Err("CertEnumCertificatesInStore: no cert found in PFX".into());
        }

        // Parametry podpisu (zeroed -> mniej problemów z typami)
        let mut para: CRYPT_SIGN_MESSAGE_PARA = std::mem::zeroed();
        para.cbSize = std::mem::size_of::<CRYPT_SIGN_MESSAGE_PARA>() as u32;
        para.dwMsgEncodingType = (X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0) as u32;
        para.pSigningCert = cert_ctx;

        // SHA256 + RSA
        para.HashAlgorithm.pszObjId = PSTR(szOID_RSA_SHA256RSA.as_ptr() as *mut u8);

        // Dołącz cert do SignedData
        para.cMsgCert = 1;
        let mut certs: [*mut CERT_CONTEXT; 1] = [cert_ctx];
        para.rgpMsgCert = certs.as_mut_ptr();

        // Dane do podpisu (1 segment)
        let rgpb: [*const u8; 1] = [data.as_ptr()];
        let rgcb: [u32; 1] = [data.len() as u32];

        // 1) zapytaj o rozmiar wyjścia
        let mut out_len: u32 = 0;
        CryptSignMessage(
            &para as *const CRYPT_SIGN_MESSAGE_PARA,
            true, // detached
            1,
            Some(rgpb.as_ptr()),
            rgcb.as_ptr(),
            None,
            &mut out_len,
        )
        .map_err(|e| format!("CryptSignMessage(size) failed: {e:?}"))?;

        // 2) wygeneruj podpis
        let mut out = vec![0u8; out_len as usize];
        CryptSignMessage(
            &para as *const CRYPT_SIGN_MESSAGE_PARA,
            true,
            1,
            Some(rgpb.as_ptr()),
            rgcb.as_ptr(),
            Some(out.as_mut_ptr()),
            &mut out_len,
        )
        .map_err(|e| format!("CryptSignMessage(sign) failed: {e:?}"))?;

        out.truncate(out_len as usize);

        // cleanup
        CertFreeCertificateContext(Some(cert_ctx as *const CERT_CONTEXT));
        let _ = CertCloseStore(Some(store), 0);

        Ok(out)
    }
}