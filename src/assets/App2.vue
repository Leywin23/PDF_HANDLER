<template>
  <main style="padding:20px">

    <label>PDF:</label>
    <input type="file" accept="application/pdf" @change="onPdfSelected" />

    <div style="margin-top:16px">
      <canvas ref="canvasRef" style="border:1px solid #ccc; max-width:100%"></canvas>
    </div>

    <div style="margin-top:24px">
      <button @click="getDeviceData">Pobierz dane urządzenia</button>

      <p>Current Location: {{ locationText }}</p>
      <p>Data i godzina: {{ dateTime }}</p>
    </div>

    <div style="margin-top:16px">
      <button :disabled="!pdfBytes" @click="signPdf">
        Sign PDF
      </button>
    </div>

  </main>
</template>

<script setup lang="ts">
import { ref } from "vue";

/* PDF.js */
import * as pdfjsLib from "pdfjs-dist/legacy/build/pdf.mjs";
import pdfWorker from "pdfjs-dist/legacy/build/pdf.worker.min.mjs?url";

/* PDF-lib */
import { PDFDocument as PDFLibDocument, StandardFonts, rgb } from "pdf-lib";

/* Geolocation */
import { checkPermissions, requestPermissions, getCurrentPosition } from "@tauri-apps/plugin-geolocation";

pdfjsLib.GlobalWorkerOptions.workerSrc = pdfWorker;

/* ===============================
   STATE
================================ */

const canvasRef = ref<HTMLCanvasElement | null>(null);
const pdfBytes = ref<Uint8Array | null>(null);

const dateTime = ref("—");
const locationText = ref("—");

/* pdf.js runtime state */
let loadingTask: any = null;
let pdfDoc: any = null;

/* ===============================
   HELPERS
================================ */

function toExactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

async function destroyPdfJsDoc() {
  try {
    if (loadingTask?.destroy) await loadingTask.destroy();
  } catch {}
  loadingTask = null;
  pdfDoc = null;
}

/* ===============================
   RENDER (reload PDF object)
================================ */

async function renderPdfFromBytes(bytes: Uint8Array, pageNumber: number) {
  try {
    // 1) Zniszcz poprzedni dokument/task (ważne na Android WebView)
    await destroyPdfJsDoc();

    // 2) Zawsze twórz NOWY dokument pdf.js
    const data = toExactArrayBuffer(bytes);
    loadingTask = pdfjsLib.getDocument({ data });
    pdfDoc = await loadingTask.promise;

    // 3) Pobierz stronę
    const safePage = Math.max(1, Math.min(pageNumber, pdfDoc.numPages));
    const page = await pdfDoc.getPage(safePage);

    const viewport = page.getViewport({ scale: 1.2 });

    const canvas = canvasRef.value;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;

    // (opcjonalnie) reset rozmiaru - pomaga na niektórych WebView
    canvas.width = 0;
    canvas.height = 0;

    canvas.width = Math.ceil(viewport.width * dpr);
    canvas.height = Math.ceil(viewport.height * dpr);

    canvas.style.width = `${Math.ceil(viewport.width)}px`;
    canvas.style.height = `${Math.ceil(viewport.height)}px`;

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    await page.render({
      canvas,              // wymagane przez typy
      canvasContext: ctx,  // OK zostawić
      viewport,
    }).promise;
  } catch (err) {
    console.error("Render error:", err);
  }
}

/* ===============================
   LOAD PDF
================================ */

async function onPdfSelected(e: Event) {
  const input = e.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;

  const ab = await file.arrayBuffer();
  pdfBytes.value = new Uint8Array(ab);

  console.log("Loaded PDF len=", pdfBytes.value.length);

  // renderuj stronę 1 po wczytaniu
  await renderPdfFromBytes(pdfBytes.value, 1);
}

/* ===============================
   DEVICE DATA
================================ */

async function getDeviceData() {
  dateTime.value = new Date().toLocaleString();

  try {
    let perms = await checkPermissions();

    if (perms.location !== "granted") {
      perms = await requestPermissions(["location"]);
    }

    if (perms.location !== "granted") {
      locationText.value = "Permission denied";
      return;
    }

    const pos = await getCurrentPosition();
    locationText.value = `${pos.coords.latitude.toFixed(6)}, ${pos.coords.longitude.toFixed(6)}`;
  } catch (err) {
    console.error(err);
    locationText.value = "Location error";
  }
}

/* ===============================
   ADD VISUAL SIGNATURE (pdf-lib)
================================ */

async function addVisualSignature(bytes: Uint8Array): Promise<Uint8Array> {
  const input = bytes.slice(); // kopia
  const pdfDoc = await PDFLibDocument.load(input);

  const pages = pdfDoc.getPages();
  const page = pages[pages.length - 1]; // ostatnia strona

  const { width } = page.getSize();

  const boxWidth = 240;
  const boxHeight = 70;
  const margin = 20;

  const x = width - boxWidth - margin;
  const y = margin;

  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const now = new Date().toLocaleString();

  page.drawRectangle({
    x,
    y,
    width: boxWidth,
    height: boxHeight,
    borderWidth: 1,
    borderColor: rgb(0.2, 0.2, 0.2),
    color: rgb(1, 1, 1),
  });

  page.drawText("Digitally signed", {
    x: x + 10,
    y: y + boxHeight - 18,
    size: 12,
    font,
    color: rgb(0.1, 0.1, 0.1),
  });

  page.drawText(`Date: ${now}`, {
    x: x + 10,
    y: y + boxHeight - 36,
    size: 10,
    font,
    color: rgb(0.2, 0.2, 0.2),
  });

  page.drawText(`Location: ${locationText.value}`, {
    x: x + 10,
    y: y + 12,
    size: 10,
    font,
    color: rgb(0.2, 0.2, 0.2),
  });

  const out = await pdfDoc.save();
  return new Uint8Array(out);
}

/* ===============================
   SIGN BUTTON
================================ */

async function signPdf() {
  try {
    console.log("[SIGN] clicked");

    if (!pdfBytes.value) {
      console.log("[SIGN] no pdfBytes");
      return;
    }

    const signed = await addVisualSignature(pdfBytes.value);
    pdfBytes.value = signed;

    // 🔥 klucz: po podpisie renderuj NOWY dokument pdf.js
    // Dodatkowo renderujemy ostatnią stronę, bo tam jest podpis.
    await renderPdfFromBytes(signed, Number.MAX_SAFE_INTEGER);

    console.log("[SIGN] done");
  } catch (err) {
    console.error("[SIGN] ERROR:", err);
  }
}
</script>