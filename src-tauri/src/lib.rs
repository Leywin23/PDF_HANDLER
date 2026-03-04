// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/

use windows::Win32::Security::Cryptography::*;
use windows::core::{PCWSTR, PSTR};

use lopdf::{Document, Object, Dictionary, StringFormat};

const SIG_PLACEHOLDER_HEX_LEN: usize = 40000;      // ile ZNAKÓW hex ma być w PDF
const SIG_PLACEHOLDER_BYTES_LEN: usize = SIG_PLACEHOLDER_HEX_LEN / 2; // 40k hex znaków = 20kB DER (zapas)

#[tauri::command]
fn greet(name: &str) -> std::string::String {
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

    // 1) dodaj placeholdery podpisu do PDF
    let pdf_with_placeholder = add_sig_placeholder(&pdf_bytes)?;
    println!("Placeholder PDF len = {}", pdf_with_placeholder.len());

    // 2) znajdź zakres /Contents <...> i policz TBS (bytes do podpisu)
    let (sig_hex_start, sig_hex_end) = find_contents_hex_range(&pdf_with_placeholder)?;
    let mut tbs = Vec::with_capacity(pdf_with_placeholder.len());
    tbs.extend_from_slice(&pdf_with_placeholder[..sig_hex_start]);
    tbs.extend_from_slice(&pdf_with_placeholder[sig_hex_end..]);

    // 3) wygeneruj CMS/PKCS#7 detached nad TBS
    let sig_der = pkcs7_detached_from_pfx(&p12_bytes, &password, &tbs)?;
    println!("CMS (PKCS#7) DER len = {} bytes", sig_der.len());

    // 4) wklej CMS do /Contents i ustaw prawdziwy /ByteRange
    let signed_pdf = patch_byte_range_and_contents(pdf_with_placeholder, &sig_der)?;
    println!("Signed PDF len = {}", signed_pdf.len());
    Ok(signed_pdf)
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

/// --- Windows CryptoAPI: PKCS#7 detached (działa z non-exportable PFX) ---
fn pkcs7_detached_from_pfx(
    pfx: &[u8],
    password: &str,
    data: &[u8],
) -> Result<Vec<u8>, std::string::String> {
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

        // Parametry podpisu
        let mut para: CRYPT_SIGN_MESSAGE_PARA = std::mem::zeroed();
        para.cbSize = std::mem::size_of::<CRYPT_SIGN_MESSAGE_PARA>() as u32;
        para.dwMsgEncodingType = (X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0) as u32;
        para.pSigningCert = cert_ctx;

        // SHA256 + RSA
        para.HashAlgorithm.pszObjId = PSTR(szOID_RSA_SHA256RSA.as_ptr() as *mut u8);

        // dołącz cert do SignedData
        para.cMsgCert = 1;
        let mut certs: [*mut CERT_CONTEXT; 1] = [cert_ctx];
        para.rgpMsgCert = certs.as_mut_ptr();

        // dane do podpisu (1 segment)
        let rgpb: [*const u8; 1] = [data.as_ptr()];
        let rgcb: [u32; 1] = [data.len() as u32];

        // 1) rozmiar
        let mut out_len: u32 = 0;
        CryptSignMessage(
            &para as *const CRYPT_SIGN_MESSAGE_PARA,
            true,
            1,
            Some(rgpb.as_ptr()),
            rgcb.as_ptr(),
            None,
            &mut out_len,
        )
        .map_err(|e| format!("CryptSignMessage(size) failed: {e:?}"))?;

        // 2) podpis
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

/// --- PDF: dodaj pole podpisu + placeholdery /Contents i /ByteRange ---
fn add_sig_placeholder(pdf: &[u8]) -> Result<Vec<u8>, std::string::String> {
    let mut doc = Document::load_mem(pdf).map_err(|e| format!("PDF load failed: {e}"))?;

    // 1) Weź catalog_id (Root) jako wartość, nie trzymaj &mut katalogu
    let catalog_id = doc
        .trailer
        .get(b"Root")
        .map_err(|e| format!("PDF: trailer Root missing: {e}"))?
        .as_reference()
        .map_err(|e| format!("PDF: Root is not reference: {e}"))?;

    // 2) /Sig dictionary
    let byte_range = Object::Array(vec![
        Object::Integer(0),
        Object::Integer(9_999_999_999),
        Object::Integer(9_999_999_999),
        Object::Integer(9_999_999_999),
    ]);

    let contents_placeholder = vec![0u8; SIG_PLACEHOLDER_BYTES_LEN]; // 0x00 -> w PDF będzie "00"
    let contents_obj = Object::String(contents_placeholder, StringFormat::Hexadecimal);

    let mut sig_dict = Dictionary::new();
    sig_dict.set("Type", Object::Name(b"Sig".to_vec()));
    sig_dict.set("Filter", Object::Name(b"Adobe.PPKLite".to_vec()));
    sig_dict.set("SubFilter", Object::Name(b"adbe.pkcs7.detached".to_vec()));
    sig_dict.set("ByteRange", byte_range);
    sig_dict.set("Contents", contents_obj);

    let sig_id = doc.new_object_id();
    doc.objects.insert(sig_id, Object::Dictionary(sig_dict));

    // 3) Widget
    let pages = doc.get_pages();
    let (_, &first_page_id) = pages.iter().next().ok_or("PDF: no pages")?;

    let mut widget = Dictionary::new();
    widget.set("Type", Object::Name(b"Annot".to_vec()));
    widget.set("Subtype", Object::Name(b"Widget".to_vec()));
    widget.set("FT", Object::Name(b"Sig".to_vec()));
    widget.set(
        "Rect",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(0),
            Object::Integer(0),
            Object::Integer(0),
        ]),
    );
    widget.set("V", Object::Reference(sig_id));
    widget.set("T", Object::String(b"Signature1".to_vec(), StringFormat::Literal));
    widget.set("F", Object::Integer(4));

    let widget_id = doc.new_object_id();
    doc.objects.insert(widget_id, Object::Dictionary(widget));

    // 4) dopnij widget do /Annots na stronie
    {
        let page_obj = doc
            .get_object_mut(first_page_id)
            .map_err(|e| format!("PDF: get page failed: {e}"))?;
        let page_dict = page_obj
            .as_dict_mut()
            .map_err(|_| "PDF: page not dict".to_string())?;

        let annots_opt = page_dict.get(b"Annots").ok().cloned();
        let new_annots = match annots_opt {
            Some(Object::Array(mut a)) => {
                a.push(Object::Reference(widget_id));
                Object::Array(a)
            }
            Some(Object::Reference(r)) => Object::Array(vec![
                Object::Reference(r),
                Object::Reference(widget_id),
            ]),
            _ => Object::Array(vec![Object::Reference(widget_id)]),
        };
        page_dict.set("Annots", new_annots);
    }

    // 5) Odczytaj (bez borrowa) czy jest AcroForm i jaki ma id
    let acro_ref: Option<lopdf::ObjectId> = {
        let catalog_obj = doc
            .get_object(catalog_id)
            .map_err(|e| format!("PDF: get catalog failed: {e}"))?;
        let catalog_dict = catalog_obj
            .as_dict()
            .map_err(|_| "PDF: catalog not dict".to_string())?;
        catalog_dict.get(b"AcroForm").and_then(Object::as_reference).ok()
    };

    // 6) Zaktualizuj AcroForm (w krótkich scope’ach)
    if let Some(acro_id) = acro_ref {
        let acro_obj = doc
            .get_object_mut(acro_id)
            .map_err(|e| format!("PDF: get AcroForm failed: {e}"))?;
        let acro_dict = acro_obj
            .as_dict_mut()
            .map_err(|_| "PDF: AcroForm not dict".to_string())?;

        let fields_opt = acro_dict.get(b"Fields").ok().cloned();
        let new_fields = match fields_opt {
            Some(Object::Array(mut a)) => {
                a.push(Object::Reference(widget_id));
                Object::Array(a)
            }
            _ => Object::Array(vec![Object::Reference(widget_id)]),
        };

        acro_dict.set("Fields", new_fields);
        acro_dict.set("SigFlags", Object::Integer(3));
    } else {
        let mut acro = Dictionary::new();
        acro.set("SigFlags", Object::Integer(3));
        acro.set("Fields", Object::Array(vec![Object::Reference(widget_id)]));
        let acro_id = doc.new_object_id();
        doc.objects.insert(acro_id, Object::Dictionary(acro));

        // teraz dopiero weź katalog mutowalnie i ustaw AcroForm
        {
            let catalog_obj = doc
                .get_object_mut(catalog_id)
                .map_err(|e| format!("PDF: get catalog mut failed: {e}"))?;
            let catalog_dict = catalog_obj
                .as_dict_mut()
                .map_err(|_| "PDF: catalog not dict".to_string())?;
            catalog_dict.set("AcroForm", Object::Reference(acro_id));
        }
    }

    // 7) zapis
    let mut out = Vec::new();
    doc.save_to(&mut out).map_err(|e| format!("PDF save failed: {e}"))?;
    Ok(out)
}

/// znajduje w bajtach PDF zakres hexa wewnątrz /Contents <...>
/// zwraca (start, end) = indeksy samego hexa (bez '<' i '>')
fn find_contents_hex_range(pdf: &[u8]) -> Result<(usize, usize), String> {
    // kotwica: nasz podpis
    let anchor = b"/SubFilter/adbe.pkcs7.detached";
    let pos = find_subslice(pdf, anchor)
        .ok_or("PDF: signature SubFilter not found (anchor)")?;

    // szukaj /Contents dopiero po anchor
    let tail = &pdf[pos..];
    let key = b"/Contents";
    let rel = find_subslice(tail, key).ok_or("PDF: /Contents after anchor not found")?;
    let base = pos + rel;

    let lt = pdf[base..]
        .iter()
        .position(|&c| c == b'<')
        .map(|i| base + i)
        .ok_or("PDF: '<' after /Contents not found")?;

    let gt = pdf[lt..]
        .iter()
        .position(|&c| c == b'>')
        .map(|i| lt + i)
        .ok_or("PDF: '>' after /Contents not found")?;

    let start = lt + 1;
    let end = gt;

    if end <= start {
        return Err("PDF: invalid /Contents range".into());
    }
    if end - start != SIG_PLACEHOLDER_HEX_LEN {
        return Err(format!(
            "PDF: unexpected /Contents placeholder len {}, expected {}",
            end - start,
            SIG_PLACEHOLDER_HEX_LEN
        ));
    }
    Ok((start, end))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Patchuje w miejscu:
/// - /Contents: wpisuje CMS hex + dopad 0 do stałej długości
/// - /ByteRange: wpisuje prawdziwe liczby z paddingiem do tej samej długości tokenów
fn patch_byte_range_and_contents(
    mut pdf: Vec<u8>,
    sig_der: &[u8],
) -> Result<Vec<u8>, std::string::String> {
    // 1) zakres /Contents <...>
    let (sig_hex_start, sig_hex_end) = find_contents_hex_range(&pdf)?;
    let file_len = pdf.len();

    // ByteRange wg offsetów hexa (wykluczamy same znaki hexa)
    let range0 = 0usize;
    let range1_len = sig_hex_start;
    let range2_start = sig_hex_end;
    let range2_len = file_len - range2_start;

    // 2) wklej podpis do /Contents jako HEX (bez zmiany długości pliku)
    let sig_hex = hex::encode_upper(sig_der);
    if sig_hex.len() > SIG_PLACEHOLDER_HEX_LEN {
        return Err(format!(
            "CMS too big: {} hex chars > placeholder {} (increase SIG_PLACEHOLDER_HEX_LEN)",
            sig_hex.len(),
            SIG_PLACEHOLDER_HEX_LEN
        ));
    }
    let mut filled = sig_hex.into_bytes();
    filled.resize(SIG_PLACEHOLDER_HEX_LEN, b'0');
    pdf[sig_hex_start..sig_hex_end].copy_from_slice(&filled);

    // 3) znajdź /ByteRange i podmień 4 liczby w miejscu
    // Szukamy pierwszego "/ByteRange" i potem parsujemy tokeny liczbowe aż do ']'
    let br_pos = find_subslice(&pdf, b"/ByteRange").ok_or("PDF: /ByteRange not found")?;
    let after = &pdf[br_pos..];

    let lb_rel = after.iter().position(|&c| c == b'[').ok_or("PDF: ByteRange '[' not found")?;
    let rb_rel = after.iter().position(|&c| c == b']').ok_or("PDF: ByteRange ']' not found")?;

    let lb = br_pos + lb_rel;
    let rb = br_pos + rb_rel;

    // wyciągnij substring wewnątrz [ ... ]
    let inside = &pdf[lb + 1..rb];

    // znajdź 4 liczby jako “tokeny” (start..end w pliku)
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut i = 0usize;
    while i < inside.len() {
        while i < inside.len() && !inside[i].is_ascii_digit() {
            i += 1;
        }
        if i >= inside.len() {
            break;
        }
        let s = i;
        while i < inside.len() && inside[i].is_ascii_digit() {
            i += 1;
        }
        let e = i;
        spans.push((lb + 1 + s, lb + 1 + e));
        if spans.len() == 4 {
            break;
        }
    }
    if spans.len() != 4 {
        return Err("PDF: couldn't parse 4 numbers in ByteRange".into());
    }

    // helper: wpisz liczbę z paddingiem do długości tokenu
    fn write_num_fixed(buf: &mut [u8], value: usize) {
        let s = value.to_string();
        // padding zerami z lewej do stałej długości
        let len = buf.len();
        let mut out = vec![b'0'; len];
        let bytes = s.as_bytes();
        if bytes.len() >= len {
            // jeśli nie mieści się, weź końcówkę (nie powinno się zdarzyć dla 10 cyfr)
            out.copy_from_slice(&bytes[bytes.len() - len..]);
        } else {
            out[len - bytes.len()..].copy_from_slice(bytes);
        }
        buf.copy_from_slice(&out);
    }

    // Token 0 w wielu PDF bywa "0" (1 znak). Zostawiamy stałą długość jak jest w pliku.
    // Reszta powinna mieć 10 cyfr bo ustawialiśmy 9999999999.
    write_num_fixed(&mut pdf[spans[0].0..spans[0].1], range0);
    write_num_fixed(&mut pdf[spans[1].0..spans[1].1], range1_len);
    write_num_fixed(&mut pdf[spans[2].0..spans[2].1], range2_start);
    write_num_fixed(&mut pdf[spans[3].0..spans[3].1], range2_len);

    Ok(pdf)
}