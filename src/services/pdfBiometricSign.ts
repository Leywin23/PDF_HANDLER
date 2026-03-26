import { invoke } from "@tauri-apps/api/core";
import { signPdfCmsWithBiometric, base64ToBytes } from "./androidSigner";

type PreparedPdfSignature = {
    pdf_with_br: number[];
    tbs: number[];
};

export async function signPdfWithAndroidBiometric(file: File) {
    const pdfBytes = new Uint8Array(await file.arrayBuffer());

    const prepared = await invoke<PreparedPdfSignature>(
        "prepare_pdf_for_external_sign",
        {
            pdfBytes: Array.from(pdfBytes),
        }
    );

    const tbs = new Uint8Array(prepared.tbs);

    const { cmsDerBase64 } = await signPdfCmsWithBiometric(tbs);
    const cmsDer = base64ToBytes(cmsDerBase64);

    const signedPdf = await invoke<number[]>("finalize_pdf_signature", {
        pdfWithBr: prepared.pdf_with_br,
        cmsDer: Array.from(cmsDer),
    });

    return new Uint8Array(signedPdf);
}

export function downloadPdf(bytes: Uint8Array, filename = "signed.pdf") {
    const blob = new Blob([bytes], { type: "application/pdf" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();

    URL.revokeObjectURL(url);
}