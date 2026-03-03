<template>
  <main>
      <label>PDF:</label>
      <input type="file" accept="application/pdf" @change="onPdfSelected" />
      <div style="margin-top: 16px;">
        <canvas ref="canvasRef" style="border: 1px solid #ccc; max-width: 100%;"></canvas>
      </div>
  </main>
</template>

<script setup lang="ts">
import * as pdfjsLib from "pdfjs-dist/legacy/build/pdf.mjs";
import pdfWorker from "pdfjs-dist/build/pdf.worker.min.mjs?url";
import { ref } from "vue";


  // Set the worker to parse PDF files
  pdfjsLib.GlobalWorkerOptions.workerSrc = pdfWorker;

  
  // Reference to the canvas element where the PDF page will be rendered
  const canvasRef = ref<HTMLCanvasElement | null>(null);

  // Handler for when a PDF file is selected
    async function onPdfSelected(e: Event){
      // Get the selected file from the input element
      const input = e.target as HTMLInputElement;
      // Take the first file from the input (if any)
      const file = input.files?.[0];
      if (!file) return;

      // Convert the file to an ArrayBuffer (binary data) for processing
      const ab = await file.arrayBuffer();
      // Create a Uint8Array from the ArrayBuffer, which is required by pdfjsLib
      const bytes = new Uint8Array(ab);

      // Load the PDF document using pdfjsLib with the provided bytes
      const pdf = await pdfjsLib.getDocument({ data: bytes }).promise;
      const page = await pdf.getPage(1);

      // Create a viewport for the page with a scale of 1.2 (120% zoom)
      const viewport = page.getViewport({ scale: 1.2 });

      // Get the canvas element and its 2D rendering context
      const canvas = canvasRef.value;
      if(!canvas) return;

      const ctx = canvas.getContext("2d");
      if(!ctx) return;

      const dpr = window.devicePixelRatio || 1;
      canvas.width = Math.ceil(viewport.width * dpr);
      canvas.height = Math.ceil(viewport.height * dpr);
      canvas.style.width = `${Math.ceil(viewport.width)}px`;
      canvas.style.height = `${Math.ceil(viewport.height)}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      await page.render({
        canvas: canvas,
        viewport,
      }).promise;
    }

</script>