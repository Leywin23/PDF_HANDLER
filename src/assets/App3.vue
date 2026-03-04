<template>
  <main style="padding:20px">

    <label>PDF:</label>
    <input type="file" accept="application/pdf" @change="onPdfSelected" />

    <div style="margin-top:16px">
      <canvas ref="canvasRef" style="border:1px solid #ccc; max-width:100%"></canvas>
    </div>

    <div style="margin-top:24px">
      <button @click="getDeviceData" :disabled="busy">
        Pobierz dane urządzenia
      </button>

      <p>Current Location: {{ locationText }}</p>
      <p>Data i godzina: {{ dateTime }}</p>
    </div>

    <div style="margin-top:16px">
      <button :disabled="!pdfBytes || busy" @click="signPdfFast">
        Sign PDF (visual)
      </button>
      <p v-if="busy">Przetwarzam...</p>
    </div>

    <hr style="margin:24px 0">

    <div>
      <label>Certyfikat (.p12/.pfx):</label>
      <input type="file"
             accept=".p12,.pfx,application/x-pkcs12"
             @change="onP12Selected" />
    </div>

    <div style="margin-top:8px">
      <label>Hasło do certyfikatu:</label>
      <input type="password" v-model="p12Password" />
    </div>

    <div style="margin-top:16px">
      <button
          @click="signWithCert"
          :disabled="busy || !pdfBytes || !p12Bytes || !p12Password">

        Podpisz certyfikatem
      </button>
    </div>

  </main>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";

/* PDF.js */
import * as pdfjsLib from "pdfjs-dist/legacy/build/pdf.mjs";
import pdfWorker from "pdfjs-dist/legacy/build/pdf.worker.min.mjs?url";

/* PDF-lib */
import { PDFDocument as PDFLibDocument, StandardFonts, rgb } from "pdf-lib";

/* Geolocation */
import {
  checkPermissions,
  requestPermissions,
  getCurrentPosition
} from "@tauri-apps/plugin-geolocation";

pdfjsLib.GlobalWorkerOptions.workerSrc = pdfWorker;

/* ================= STATE ================= */

const canvasRef = ref<HTMLCanvasElement | null>(null);

const pdfBytes = ref<Uint8Array | null>(null);

const p12Bytes = ref<Uint8Array | null>(null);
const p12Password = ref("");

const dateTime = ref("—");
const locationText = ref("—");

const busy = ref(false);

/* pdf.js state */
let loadingTask: any = null;
let pdfDoc: any = null;

/* ================= PERF ================= */

const RENDER_SCALE = 1.0;
const RENDER_DPR = 1;

/* ================= HELPERS ================= */

function toExactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function nextFrame(): Promise<void> {
  return new Promise((r) => requestAnimationFrame(() => r()));
}

async function destroyPdfJs() {
  try {
    if (loadingTask?.destroy) await loadingTask.destroy();
  } catch {}

  loadingTask = null;
  pdfDoc = null;
}

/* ================= LOAD PDF ================= */

async function loadPdfJsDoc(bytes: Uint8Array) {
  await destroyPdfJs();

  const data = toExactArrayBuffer(bytes);
  loadingTask = pdfjsLib.getDocument({ data });

  pdfDoc = await loadingTask.promise;
}

async function renderPage(pageNumber: number) {

  if (!pdfDoc) return;

  const safePage = Math.max(1, Math.min(pageNumber, pdfDoc.numPages));
  const page = await pdfDoc.getPage(safePage);

  const viewport = page.getViewport({ scale: RENDER_SCALE });

  const canvas = canvasRef.value;
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  canvas.width = Math.ceil(viewport.width * RENDER_DPR);
  canvas.height = Math.ceil(viewport.height * RENDER_DPR);

  canvas.style.width = `${Math.ceil(viewport.width)}px`;
  canvas.style.height = `${Math.ceil(viewport.height)}px`;

  ctx.setTransform(RENDER_DPR, 0, 0, RENDER_DPR, 0, 0);
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  await page.render({
    canvas,
    canvasContext: ctx,
    viewport
  }).promise;
}

/* ================= PDF SELECT ================= */

async function onPdfSelected(e: Event) {

  const input = e.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;

  busy.value = true;

  try {

    const ab = await file.arrayBuffer();
    pdfBytes.value = new Uint8Array(ab);

    await loadPdfJsDoc(pdfBytes.value);
    await renderPage(1);

  } finally {
    busy.value = false;
  }
}

/* ================= GEO ================= */

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

    locationText.value =
        `${pos.coords.latitude.toFixed(6)}, ${pos.coords.longitude.toFixed(6)}`;

  } catch (err) {

    console.error(err);
    locationText.value = "Location error";

  }
}

/* ================= VISUAL SIGN ================= */

async function addVisualSignatureFast(bytes: Uint8Array): Promise<Uint8Array> {

  const doc = await PDFLibDocument.load(bytes);

  const pages = doc.getPages();
  const page = pages[pages.length - 1];

  const { width } = page.getSize();

  const boxWidth = 240;
  const boxHeight = 70;

  const margin = 20;

  const x = width - boxWidth - margin;
  const y = margin;

  const font = await doc.embedFont(StandardFonts.Helvetica);

  const now = new Date().toLocaleString();

  page.drawRectangle({
    x,
    y,
    width: boxWidth,
    height: boxHeight,
    borderWidth: 1,
    borderColor: rgb(0.2, 0.2, 0.2),
    color: rgb(1, 1, 1)
  });

  page.drawText("Digitally signed", {
    x: x + 10,
    y: y + boxHeight - 18,
    size: 12,
    font
  });

  page.drawText(`Date: ${now}`, {
    x: x + 10,
    y: y + boxHeight - 36,
    size: 10,
    font
  });

  page.drawText(`Location: ${locationText.value}`, {
    x: x + 10,
    y: y + 12,
    size: 10,
    font
  });

  const out = await doc.save();

  return new Uint8Array(out);
}

async function signPdfFast() {

  if (!pdfBytes.value) return;

  busy.value = true;

  try {

    if (locationText.value === "—") {
      await getDeviceData();
      await nextFrame();
    }

    const signed = await addVisualSignatureFast(pdfBytes.value);

    pdfBytes.value = signed;

    await loadPdfJsDoc(signed);

    await renderPage(Number.MAX_SAFE_INTEGER);

  } finally {

    busy.value = false;

  }
}

/* ================= CERT SELECT ================= */

async function onP12Selected(e: Event) {

  const input = e.target as HTMLInputElement;
  const file = input.files?.[0];

  if (!file) return;

  const ab = await file.arrayBuffer();

  p12Bytes.value = new Uint8Array(ab);
}

/* ================= SIGN WITH CERT ================= */

async function signWithCert() {

  if (!pdfBytes.value || !p12Bytes.value) return;

  busy.value = true;
  if (locationText.value === "—" || dateTime.value === "—") {
    await getDeviceData();
  }

  try {

    const signed: number[] = await invoke("sign_pdf_pades", {
      pdfBytes: Array.from(pdfBytes.value!),
      p12Bytes: Array.from(p12Bytes.value!),
      password: p12Password.value,
      reason: "Signed in app",
      location: locationText.value,
      signingTime: dateTime.value,
    });

    pdfBytes.value = new Uint8Array(signed);

    await loadPdfJsDoc(pdfBytes.value);

    await renderPage(Number.MAX_SAFE_INTEGER);

  } catch (err) {

    console.error("SIGN ERROR:", err);

  } finally {

    busy.value = false;

  }
}
</script>