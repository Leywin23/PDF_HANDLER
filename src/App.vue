<template>
  <main class="app-shell">
    <section class="hero-card">
      <div>
        <p class="eyebrow">PDF Signer</p>
        <h1>Podpis elektroniczny PDF</h1>
        <p class="hero-text">
          Wczytaj dokument, sprawdź podgląd, dodaj podpis wizualny i podpisz plik
          certyfikatem albo Android Keystore.
        </p>
      </div>

      <div class="status-pill" :class="busy ? 'status-pill--busy' : 'status-pill--ready'">
        <span class="status-dot"></span>
        {{ busy ? "Przetwarzanie" : "Gotowe do pracy" }}
      </div>
    </section>

    <section class="content-grid">
      <div class="panel panel--preview">
        <div class="panel-header">
          <div>
            <h2>Podgląd dokumentu</h2>
            <p>Zobacz aktualną wersję PDF przed pobraniem lub podpisaniem.</p>
          </div>
        </div>

        <label class="field-label">PDF</label>
        <label class="file-input">
          <input type="file" accept="application/pdf" @change="onPdfSelected" />
          <span>{{ pdfBytes ? "Zmień dokument PDF" : "Wybierz dokument PDF" }}</span>
        </label>

        <div class="preview-frame" :class="{ 'preview-frame--empty': !pdfBytes }">
          <div class="pdf-stage" v-show="pdfBytes">
            <canvas ref="canvasRef" class="pdf-canvas"></canvas>
            <canvas
                v-show="pdfBytes && visualSignMode === 'draw'"
                ref="drawCanvasRef"
                class="draw-canvas"
                @pointerdown="startDrawing"
                @pointermove="drawMove"
                @pointerup="stopDrawing"
                @pointercancel="stopDrawing"
                @pointerleave="stopDrawing"
            ></canvas>
          </div>

          <div v-if="!pdfBytes" class="empty-state">
            <strong>Brak wczytanego dokumentu</strong>
            <span>Dodaj plik PDF, aby zobaczyć podgląd.</span>
          </div>
        </div>
      </div>

      <div class="side-column">
        <div class="panel">
          <div class="panel-header">
            <div>
              <h2>Dane urządzenia</h2>
              <p>Lokalizacja i czas mogą zostać użyte w podpisie wizualnym.</p>
            </div>
          </div>

          <button class="btn btn-secondary btn-full" @click="getDeviceData" :disabled="busy">
            Pobierz dane urządzenia
          </button>

          <div class="info-list">
            <div class="info-item">
              <span class="info-label">Lokalizacja</span>
              <span class="info-value">{{ locationText }}</span>
            </div>
            <div class="info-item">
              <span class="info-label">Data i godzina</span>
              <span class="info-value">{{ dateTime }}</span>
            </div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-header">
            <div>
              <h2>Tryb podpisu wizualnego</h2>
              <p>Wybierz szybki podpis lub ręczne rysowanie na dokumencie.</p>
            </div>
          </div>

          <div class="mode-switch">
            <button
                class="mode-btn"
                :class="{ 'mode-btn--active': visualSignMode === 'click' }"
                @click="visualSignMode = 'click'"
                type="button"
            >
              Kliknięciem
            </button>

            <button
                class="mode-btn"
                :class="{ 'mode-btn--active': visualSignMode === 'draw' }"
                @click="activateDrawMode"
                type="button"
                :disabled="!pdfBytes"
            >
              Ręcznie
            </button>
          </div>

          <div class="action-grid">
            <button
                class="btn btn-secondary"
                :disabled="!pdfBytes || busy"
                @click="applyVisualSignature"
            >
              Dodaj podpis wizualny
            </button>

            <button
                v-if="visualSignMode === 'draw'"
                class="btn btn-ghost"
                type="button"
                @click="clearDrawing"
                :disabled="busy || !pdfBytes"
            >
              Wyczyść rysunek
            </button>
          </div>
        </div>

        <div class="panel">
          <div class="panel-header">
            <div>
              <h2>Certyfikat</h2>
              <p>Wczytaj plik P12/PFX i podaj hasło do podpisania dokumentu.</p>
            </div>
          </div>

          <label class="field-label">Certyfikat (.p12 / .pfx)</label>
          <label class="file-input">
            <input
                type="file"
                accept=".p12,.pfx,application/x-pkcs12"
                @change="onP12Selected"
            />
            <span>{{ p12Bytes ? "Zmień certyfikat" : "Wybierz certyfikat" }}</span>
          </label>

          <div class="field-group">
            <label class="field-label" for="p12Password">Hasło do certyfikatu</label>
            <input
                id="p12Password"
                class="text-input"
                type="password"
                v-model="p12Password"
                placeholder="Wpisz hasło"
            />
          </div>

          <div class="action-grid">
            <button
                class="btn btn-primary"
                @click="signWithCert"
                :disabled="busy || !pdfBytes || !p12Bytes || !p12Password"
            >
              Podpisz certyfikatem
            </button>

            <button
                class="btn btn-primary"
                @click="signWithAndroidKey"
                :disabled="!pdfBytes || busy"
            >
              Podpisz Android Keystore
            </button>

            <button class="btn btn-ghost" @click="downloadPdf" :disabled="busy || !pdfBytes">
              Pobierz PDF
            </button>
          </div>

          <p v-if="busy" class="busy-text">Przetwarzam dokument, proszę czekać...</p>
        </div>
      </div>
    </section>
  </main>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { authenticate, checkStatus } from "@tauri-apps/plugin-biometric";

/* PDF.js */
import * as pdfjsLib from "pdfjs-dist/legacy/build/pdf.mjs";
import pdfWorker from "pdfjs-dist/legacy/build/pdf.worker.min.mjs?url";

/* PDF-lib */
import { PDFDocument as PDFLibDocument, StandardFonts, rgb } from "pdf-lib";

/* Geolocation */
import {
  checkPermissions,
  requestPermissions,
  getCurrentPosition,
} from "@tauri-apps/plugin-geolocation";

pdfjsLib.GlobalWorkerOptions.workerSrc = pdfWorker;

const canvasRef = ref<HTMLCanvasElement | null>(null);
const drawCanvasRef = ref<HTMLCanvasElement | null>(null);

const pdfBytes = ref<Uint8Array | null>(null);
const p12Bytes = ref<Uint8Array | null>(null);
const p12Password = ref("");

const dateTime = ref("—");
const locationText = ref("—");
const busy = ref(false);

const visualSignMode = ref<"click" | "draw">("click");
const isDrawing = ref(false);

let lastPoint: { x: number; y: number } | null = null;
let loadingTask: any = null;
let pdfDoc: any = null;

const RENDER_SCALE = 1.0;
const RENDER_DPR = 1;

function toExactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = bytes.slice();
  return copy.buffer;
}

function nextFrame(): Promise<void> {
  return new Promise((resolve) => requestAnimationFrame(() => resolve()));
}

async function destroyPdfJs() {
  try {
    if (loadingTask?.destroy) await loadingTask.destroy();
  } catch {
    // ignore
  }
  loadingTask = null;
  pdfDoc = null;
}

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

  await page.render({ canvas, canvasContext: ctx, viewport }).promise;

  syncDrawCanvas();
}

function syncDrawCanvas() {
  const pdfCanvas = canvasRef.value;
  const drawCanvas = drawCanvasRef.value;
  if (!pdfCanvas || !drawCanvas) return;

  drawCanvas.width = pdfCanvas.width;
  drawCanvas.height = pdfCanvas.height;
  drawCanvas.style.width = pdfCanvas.style.width;
  drawCanvas.style.height = pdfCanvas.style.height;

  const ctx = drawCanvas.getContext("2d");
  if (!ctx) return;

  ctx.lineCap = "round";
  ctx.lineJoin = "round";
  ctx.strokeStyle = "#111827";
  ctx.lineWidth = 2.5;
}

function activateDrawMode() {
  visualSignMode.value = "draw";
  nextFrame().then(() => syncDrawCanvas());
}

function getDrawPoint(e: PointerEvent) {
  const canvas = drawCanvasRef.value;
  if (!canvas) return null;

  const rect = canvas.getBoundingClientRect();
  return {
    x: ((e.clientX - rect.left) / rect.width) * canvas.width,
    y: ((e.clientY - rect.top) / rect.height) * canvas.height,
  };
}

function startDrawing(e: PointerEvent) {
  if (visualSignMode.value !== "draw") return;

  e.preventDefault();

  const canvas = drawCanvasRef.value;
  if (!canvas) return;

  canvas.setPointerCapture?.(e.pointerId);
  isDrawing.value = true;
  lastPoint = getDrawPoint(e);
}

function drawMove(e: PointerEvent) {
  if (!isDrawing.value || visualSignMode.value !== "draw") return;

  e.preventDefault();

  const canvas = drawCanvasRef.value;
  const point = getDrawPoint(e);
  if (!canvas || !point || !lastPoint) return;

  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  ctx.beginPath();
  ctx.moveTo(lastPoint.x, lastPoint.y);
  ctx.lineTo(point.x, point.y);
  ctx.stroke();

  lastPoint = point;
}

function stopDrawing() {
  isDrawing.value = false;
  lastPoint = null;
}

function clearDrawing() {
  const canvas = drawCanvasRef.value;
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  ctx.clearRect(0, 0, canvas.width, canvas.height);
}

async function addManualSignature(bytes: Uint8Array): Promise<Uint8Array> {
  const drawCanvas = drawCanvasRef.value;
  if (!drawCanvas) return bytes;

  const dataUrl = drawCanvas.toDataURL("image/png");
  const base64 = dataUrl.split(",")[1];
  const binary = atob(base64);
  const pngBytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    pngBytes[i] = binary.charCodeAt(i);
  }

  const doc = await PDFLibDocument.load(bytes);
  const pages = doc.getPages();
  const page = pages[pages.length - 1];

  const pngImage = await doc.embedPng(pngBytes);
  const pageWidth = page.getWidth();
  const pageHeight = page.getHeight();

  page.drawImage(pngImage, {
    x: 0,
    y: 0,
    width: pageWidth,
    height: pageHeight,
  });

  const out = await doc.save();
  return new Uint8Array(out);
}

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
    color: rgb(1, 1, 1),
  });

  page.drawText("Digitally signed", {
    x: x + 10,
    y: y + boxHeight - 18,
    size: 12,
    font,
  });

  page.drawText(`Date: ${now}`, {
    x: x + 10,
    y: y + boxHeight - 36,
    size: 10,
    font,
  });

  page.drawText(`Location: ${locationText.value}`, {
    x: x + 10,
    y: y + 12,
    size: 10,
    font,
  });

  const out = await doc.save();
  return new Uint8Array(out);
}

async function applyVisualSignature() {
  if (!pdfBytes.value) return;

  busy.value = true;
  try {
    if (locationText.value === "—") {
      await getDeviceData();
      await nextFrame();
    }

    let updated: Uint8Array;

    if (visualSignMode.value === "click") {
      updated = await addVisualSignatureFast(pdfBytes.value);
    } else {
      updated = await addManualSignature(pdfBytes.value);
      clearDrawing();
    }

    pdfBytes.value = updated;
    await loadPdfJsDoc(updated);
    await renderPage(Number.MAX_SAFE_INTEGER);
  } finally {
    busy.value = false;
  }
}

function downloadPdf() {
  if (!pdfBytes.value) return;

  const ab = toExactArrayBuffer(pdfBytes.value);
  const blob = new Blob([ab], { type: "application/pdf" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = "signed.pdf";
  a.click();

  URL.revokeObjectURL(url);
}

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

async function onP12Selected(e: Event) {
  const input = e.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;

  const ab = await file.arrayBuffer();
  p12Bytes.value = new Uint8Array(ab);
}

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

async function requireBiometric(): Promise<boolean> {
  // Na desktopie plugin biometric nie jest zarejestrowany – przepuść bez weryfikacji
  const isMobile = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent) ||
      ('ontouchstart' in window && navigator.maxTouchPoints > 1);

  if (!isMobile) return true;

  try {
    const status = await checkStatus();
    if (!status.isAvailable) return true;

    await authenticate("Potwierdź tożsamość odciskiem palca, aby podpisać dokument", {
      allowDeviceCredential: false,
    });
    return true;
  } catch (err) {
    console.warn("Biometric auth failed or cancelled:", err);
    return false;
  }
}

async function signWithCert() {
  if (!pdfBytes.value || !p12Bytes.value) return;

  const verified = await requireBiometric();
  if (!verified) return;

  busy.value = true;
  try {
    if (locationText.value === "—" || dateTime.value === "—") {
      await getDeviceData();
      await nextFrame();
    }

    const signed = await invoke<number[]>("sign_pdf_pades", {
      pdfBytes: Array.from(pdfBytes.value),
      p12Bytes: Array.from(p12Bytes.value),
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

async function signPdfWithAndroidKeystore(currentPdfBytes: Uint8Array) {
  const prepared = await invoke<{ pdf_with_br: number[]; tbs: number[] }>(
      "prepare_pdf_for_external_sign",
      {
        pdfBytes: Array.from(currentPdfBytes),
      }
  );

  const signed = await invoke<{ cmsDer: number[] }>(
      "plugin:keystore|keystoreSign",
      {
        alias: "pdf_sign_key",
        tbs: prepared.tbs,
      }
  );

  const finalPdf = await invoke<number[]>("finalize_pdf_signature", {
    pdfWithBr: prepared.pdf_with_br,
    cmsDer: signed.cmsDer,
  });

  return new Uint8Array(finalPdf);
}

async function signWithAndroidKey() {
  if (!pdfBytes.value) return;

  const verified = await requireBiometric();
  if (!verified) return;

  busy.value = true;
  try {
    const signed = await signPdfWithAndroidKeystore(pdfBytes.value);
    pdfBytes.value = signed;

    await loadPdfJsDoc(signed);
    await renderPage(Number.MAX_SAFE_INTEGER);
  } catch (err) {
    console.error("ANDROID KEYSTORE SIGN ERROR:", err);
  } finally {
    busy.value = false;
  }
}
</script>

<style scoped>
.app-shell {
  min-height: 100vh;
  min-height: 100dvh;
  background: #f1f5f9;
  color: #0f172a;
  padding: 20px;
  padding-bottom: calc(20px + env(safe-area-inset-bottom, 0px));
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.hero-card {
  max-width: 1200px;
  width: 100%;
  margin: 0 auto;
  background: linear-gradient(135deg, #0f172a, #1e293b);
  color: white;
  border-radius: 24px;
  padding: 24px;
  box-sizing: border-box;
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 18px;
}

.eyebrow {
  margin: 0 0 8px;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: #93c5fd;
  font-weight: 700;
}

.hero-card h1 {
  margin: 0 0 10px;
  font-size: 30px;
  line-height: 1.1;
}

.hero-text {
  margin: 0;
  max-width: 680px;
  color: #cbd5e1;
}

.status-pill {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  border-radius: 999px;
  font-weight: 700;
  font-size: 14px;
  white-space: nowrap;
}

.status-pill--busy {
  background: rgba(251, 191, 36, 0.18);
  color: #fde68a;
}

.status-pill--ready {
  background: rgba(34, 197, 94, 0.18);
  color: #bbf7d0;
}

.status-dot {
  width: 10px;
  height: 10px;
  border-radius: 999px;
  background: currentColor;
}

.content-grid {
  max-width: 1200px;
  width: 100%;
  margin: 0 auto;
  display: grid;
  grid-template-columns: minmax(0, 1fr) 360px;
  gap: 20px;
  align-items: start;
}

.side-column {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.panel {
  background: white;
  border-radius: 22px;
  padding: 20px;
  box-sizing: border-box;
  box-shadow: 0 12px 32px rgba(15, 23, 42, 0.08);
}

.panel--preview {
  min-width: 0;
}

.panel-header {
  margin-bottom: 16px;
}

.panel-header h2 {
  margin: 0 0 4px;
  font-size: 20px;
}

.panel-header p {
  margin: 0;
  color: #64748b;
  font-size: 14px;
}

.field-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.field-label {
  display: block;
  margin-bottom: 8px;
  font-size: 13px;
  font-weight: 700;
  color: #334155;
}

.file-input {
  display: block;
  margin-bottom: 14px;
}

.file-input input {
  display: none;
}

.file-input span {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 44px;
  padding: 10px 14px;
  background: #eff6ff;
  color: #1d4ed8;
  border: 1px solid #bfdbfe;
  border-radius: 12px;
  font-weight: 700;
  cursor: pointer;
  box-sizing: border-box;
}

.text-input {
  width: 100%;
  box-sizing: border-box;
  min-height: 44px;
  border: 1px solid #cbd5e1;
  border-radius: 12px;
  padding: 10px 12px;
  font-size: 14px;
  outline: none;
}

.text-input:focus {
  border-color: #2563eb;
}

.preview-frame {
  position: relative;
  background: #e2e8f0;
  border-radius: 18px;
  min-height: 360px;
  padding: 12px;
  box-sizing: border-box;
  display: flex;
  align-items: center;
  justify-content: center;
}

.preview-frame--empty {
  background: #f8fafc;
  border: 2px dashed #cbd5e1;
}

.pdf-stage {
  position: relative;
  width: fit-content;
  max-width: 100%;
  margin: 0 auto;
}

.pdf-canvas,
.draw-canvas {
  display: block;
  max-width: 100%;
  border-radius: 14px;
}

.draw-canvas {
  position: absolute;
  inset: 0;
  pointer-events: auto;
  touch-action: none;
  cursor: crosshair;
  background: transparent;
}

.empty-state {
  text-align: center;
  color: #64748b;
  font-size: 14px;
}

.empty-state strong {
  display: block;
  margin-bottom: 4px;
  font-size: 16px;
  color: #334155;
}

.info-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-top: 14px;
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 12px;
  border-radius: 12px;
  background: #f8fafc;
}

.info-label {
  font-size: 12px;
  font-weight: 700;
  color: #64748b;
}

.info-value {
  font-size: 14px;
  color: #0f172a;
  word-break: break-word;
}

.mode-switch {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.mode-btn {
  border: 1px solid #cbd5e1;
  background: white;
  color: #0f172a;
  border-radius: 12px;
  padding: 10px 14px;
  font-weight: 700;
  cursor: pointer;
}

.mode-btn--active {
  background: #2563eb;
  border-color: #2563eb;
  color: white;
}

.action-grid {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-top: 16px;
}

.btn {
  border: none;
  border-radius: 12px;
  min-height: 46px;
  padding: 10px 14px;
  font-size: 14px;
  font-weight: 700;
  cursor: pointer;
}

.btn-full {
  width: 100%;
}

.btn-primary {
  background: #2563eb;
  color: white;
}

.btn-secondary {
  background: #0f172a;
  color: white;
}

.btn-ghost {
  background: white;
  color: #0f172a;
  border: 1px solid #cbd5e1;
}

.btn:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

.busy-text {
  margin: 14px 0 0;
  font-size: 13px;
  color: #475569;
}

@media (max-width: 900px) {
  .content-grid {
    grid-template-columns: 1fr;
  }

  .side-column {
    order: -1;
  }
}

@media (max-width: 720px) {
  .app-shell {
    padding: 14px;
    padding-bottom: calc(18px + env(safe-area-inset-bottom, 0px));
    gap: 14px;
  }

  .hero-card {
    flex-direction: column;
    border-radius: 18px;
    padding: 18px;
  }

  .hero-card h1 {
    font-size: 24px;
  }

  .panel {
    border-radius: 18px;
    padding: 14px;
  }

  .preview-frame {
    min-height: 240px;
    padding: 8px;
  }

  .mode-switch {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
  }

  .mode-btn,
  .btn {
    min-height: 46px;
  }

  .side-column {
    margin-bottom: calc(10px + env(safe-area-inset-bottom, 0px));
  }
}
</style>