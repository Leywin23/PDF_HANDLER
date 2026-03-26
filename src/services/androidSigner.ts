import { invoke } from "@tauri-apps/api/core";

export type EnsureKeyResult = {
    alias: string;
    certDerBase64: string;
};

export type SignPdfCmsResult = {
    cmsDerBase64: string;
    certDerBase64: string;
};

function bytesToBase64(bytes: Uint8Array): string {
    let binary = "";
    const chunk = 0x8000;

    for (let i = 0; i < bytes.length; i += chunk) {
        binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }

    return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
    const binary = atob(base64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        out[i] = binary.charCodeAt(i);
    }
    return out;
}

export async function ensureAndroidSigningKey() {
    return await invoke<EnsureKeyResult>(
        "plugin:pdf-biometric-signer|ensureKey"
    );
}

export async function signPdfCmsWithBiometric(tbs: Uint8Array) {
    return await invoke<SignPdfCmsResult>(
        "plugin:pdf-biometric-signer|signPdfCms",
        {
            tbsBase64: bytesToBase64(tbs),
            promptTitle: "Podpisz PDF",
            promptSubtitle: "Potwierdź podpis odciskiem palca",
            promptDescription: "Klucz prywatny pozostaje w Android Keystore",
            negativeButtonText: "Anuluj",
        }
    );
}