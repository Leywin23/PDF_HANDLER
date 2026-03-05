// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/

use windows::Win32::Security::Cryptography::*;
use windows::core::{PCWSTR, PSTR};

use lopdf::{Document, Object, Dictionary, StringFormat};

const SIG_PLACEHOLDER_HEX_LEN: usize = 40000;
const SIG_PLACEHOLDER_BYTES_LEN: usize = SIG_PLACEHOLDER_HEX_LEN / 2;

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

    // 1. placeholder podpisu
    let pdf_with_placeholder = add_sig_placeholder(&pdf_bytes)?;

    // 2. ustaw prawdziwy ByteRange
    let pdf_with_br = patch_byte_range_only(pdf_with_placeholder)?;

    // 3. policz TBS
    let (cut_start, cut_end, _hex_start, _hex_end) = find_sig_contents_ranges(&pdf_with_br)?;
    let mut tbs = Vec::new();
    tbs.extend_from_slice(&pdf_with_br[..cut_start]);
    tbs.extend_from_slice(&pdf_with_br[cut_end..]);

    // 4. podpis CMS
    let sig_der = pkcs7_detached_from_pfx(&p12_bytes, &password, &tbs)?;
    println!("CMS len = {}", sig_der.len());

    // 5. wklej CMS
    let signed_pdf = patch_contents_only(pdf_with_br, &sig_der)?;
    println!("Signed PDF len = {}", signed_pdf.len());
    println!("Signed PDF head = {:?}", &signed_pdf[..std::cmp::min(12, signed_pdf.len())]);
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

fn pkcs7_detached_from_pfx(
    pfx: &[u8],
    password: &str,
    data: &[u8],
) -> Result<Vec<u8>, String> {

    unsafe {

        let mut blob = CRYPT_INTEGER_BLOB {
            cbData: pfx.len() as u32,
            pbData: pfx.as_ptr() as *mut u8,
        };

        let mut pw: Vec<u16> = password.encode_utf16().collect();
        pw.push(0);

        let store = PFXImportCertStore(&mut blob, PCWSTR(pw.as_ptr()), CRYPT_USER_KEYSET)
            .map_err(|e| format!("PFXImportCertStore failed: {e:?}"))?;

        let cert_ctx = CertEnumCertificatesInStore(store, None);

        if cert_ctx.is_null() {
            return Err("no cert".into());
        }

        let mut para: CRYPT_SIGN_MESSAGE_PARA = std::mem::zeroed();

        para.cbSize = std::mem::size_of::<CRYPT_SIGN_MESSAGE_PARA>() as u32;
        para.dwMsgEncodingType = (X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0) as u32;
        para.pSigningCert = cert_ctx;
        para.HashAlgorithm.pszObjId = PSTR(szOID_RSA_SHA256RSA.as_ptr() as *mut u8);

        para.cMsgCert = 1;

        let mut certs = [cert_ctx];
        para.rgpMsgCert = certs.as_mut_ptr();

        let rgpb = [data.as_ptr()];
        let rgcb = [data.len() as u32];

        let mut out_len = 0;

        CryptSignMessage(
            &para,
            true,
            1,
            Some(rgpb.as_ptr()),
            rgcb.as_ptr(),
            None,
            &mut out_len,
        ).map_err(|e| format!("{e:?}"))?;

        let mut out = vec![0u8; out_len as usize];

        CryptSignMessage(
            &para,
            true,
            1,
            Some(rgpb.as_ptr()),
            rgcb.as_ptr(),
            Some(out.as_mut_ptr()),
            &mut out_len,
        ).map_err(|e| format!("{e:?}"))?;

        Ok(out)
    }
}

fn add_sig_placeholder(pdf: &[u8]) -> Result<Vec<u8>, String> {
    let mut doc = Document::load_mem(pdf).map_err(|e| format!("PDF load failed: {e}"))?;

    // Root (Catalog)
    let catalog_id = doc
        .trailer
        .get(b"Root")
        .map_err(|e| format!("PDF: trailer Root missing: {e}"))?
        .as_reference()
        .map_err(|e| format!("PDF: Root is not reference: {e}"))?;

    // --- Sig dict ---
    let byte_range = Object::Array(vec![
        Object::Integer(0),
        Object::Integer(9_999_999_999),
        Object::Integer(9_999_999_999),
        Object::Integer(9_999_999_999),
    ]);

    let contents_placeholder = vec![0u8; SIG_PLACEHOLDER_BYTES_LEN]; // 0x00 -> "00" in hex
    let contents_obj = Object::String(contents_placeholder, StringFormat::Hexadecimal);

    let mut sig_dict = Dictionary::new();
    sig_dict.set("Type", Object::Name(b"Sig".to_vec()));
    sig_dict.set("Filter", Object::Name(b"Adobe.PPKLite".to_vec()));
    sig_dict.set("SubFilter", Object::Name(b"adbe.pkcs7.detached".to_vec()));
    sig_dict.set("ByteRange", byte_range);
    sig_dict.set("Contents", contents_obj);

    let sig_id = doc.new_object_id();
    doc.objects.insert(sig_id, Object::Dictionary(sig_dict));

    // --- Widget annot ---
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

    // dopnij widget do /Annots (NIE NADPISUJ)
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

    // --- AcroForm ---
    let acro_ref: Option<lopdf::ObjectId> = {
        let catalog_obj = doc
            .get_object(catalog_id)
            .map_err(|e| format!("PDF: get catalog failed: {e}"))?;
        let catalog_dict = catalog_obj
            .as_dict()
            .map_err(|_| "PDF: catalog not dict".to_string())?;
        catalog_dict.get(b"AcroForm").and_then(Object::as_reference).ok()
    };

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

        let catalog_obj = doc
            .get_object_mut(catalog_id)
            .map_err(|e| format!("PDF: get catalog mut failed: {e}"))?;
        let catalog_dict = catalog_obj
            .as_dict_mut()
            .map_err(|_| "PDF: catalog not dict".to_string())?;
        catalog_dict.set("AcroForm", Object::Reference(acro_id));
    }

    let mut out = Vec::new();
    doc.save_to(&mut out).map_err(|e| format!("PDF save failed: {e}"))?;
    Ok(out)
}

fn find_subslice(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn find_sig_contents_ranges(pdf: &[u8]) -> Result<(usize, usize, usize, usize), String> {

    let anchor = find_subslice(pdf, b"/SubFilter").ok_or("no sig")?;

    let tail = &pdf[anchor..];

    let contents = find_subslice(tail, b"/Contents").unwrap() + anchor;

    let lt = pdf[contents..].iter().position(|&c| c == b'<').unwrap() + contents;
    let gt = pdf[lt..].iter().position(|&c| c == b'>').unwrap() + lt;

    let hex_start = lt + 1;
    let hex_end = gt;

    let cut_start = lt;
    let cut_end = gt + 1;

    Ok((cut_start, cut_end, hex_start, hex_end))
}

fn patch_byte_range_only(mut pdf: Vec<u8>) -> Result<Vec<u8>, String> {

    let (cut_start, cut_end, _, _) = find_sig_contents_ranges(&pdf)?;

    let file_len = pdf.len();

    let range = [
        0,
        cut_start,
        cut_end,
        file_len - cut_end
    ];

    let pos = find_subslice(&pdf, b"/ByteRange").unwrap();

    let lb = find_subslice(&pdf[pos..], b"[")
        .unwrap() + pos;

    let rb = find_subslice(&pdf[pos..], b"]")
        .unwrap() + pos;

    let inside = &pdf[lb + 1..rb];

    let mut spans = Vec::new();

    let mut i = 0;

    while i < inside.len() {

        while i < inside.len() && !inside[i].is_ascii_digit() {
            i += 1;
        }

        if i >= inside.len() { break }

        let s = i;

        while i < inside.len() && inside[i].is_ascii_digit() {
            i += 1;
        }

        let e = i;

        spans.push((lb + 1 + s, lb + 1 + e));

        if spans.len() == 4 { break }
    }

    for (i,(s,e)) in spans.iter().enumerate() {

        let len = e-s;

        let val = range[i].to_string();

        let mut buf = vec![b'0'; len];

        buf[len-val.len()..].copy_from_slice(val.as_bytes());

        pdf[*s..*e].copy_from_slice(&buf);
    }

    Ok(pdf)
}

fn patch_contents_only(mut pdf: Vec<u8>, sig_der: &[u8]) -> Result<Vec<u8>, String> {

    let (_,_,hex_start,hex_end) = find_sig_contents_ranges(&pdf)?;

    let mut hex = hex::encode_upper(sig_der).into_bytes();

    hex.resize(SIG_PLACEHOLDER_HEX_LEN, b'0');

    pdf[hex_start..hex_end].copy_from_slice(&hex);

    Ok(pdf)
}