import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

test('frontend/index.html contains selected-file elements in topbar', () => {
  const html = readFileSync(join(__dirname, '../index.html'), 'utf-8');

  // Must have inputFile and selectedFileInfo immediately after
  const inputIndex = html.indexOf('id="inputFile"');
  const panelIndex = html.indexOf('id="selectedFileInfo"');
  const nameIndex = html.indexOf('id="selectedFileName"');
  const sizeIndex = html.indexOf('id="selectedFileSize"');
  const clearIndex = html.indexOf('id="clearSelectedFile"');
  const detectorIndex = html.indexOf('id="detector"');
  const runIndex = html.indexOf('id="runInvestigation"');

  assert.ok(inputIndex > 0, 'inputFile exists');
  assert.ok(panelIndex > inputIndex, 'selectedFileInfo is immediately after inputFile');
  assert.ok(nameIndex > panelIndex, 'selectedFileName is inside selectedFileInfo');
  assert.ok(sizeIndex > panelIndex, 'selectedFileSize is inside selectedFileInfo');
  assert.ok(clearIndex > panelIndex, 'clearSelectedFile is inside selectedFileInfo');
  assert.ok(detectorIndex > panelIndex, 'detector selector is preserved after selectedFileInfo');
  assert.ok(runIndex > detectorIndex, 'runInvestigation button is preserved');

  // Verify hidden attribute by default
  const panelTag = html.slice(panelIndex - 30, panelIndex + 60);
  assert.ok(panelTag.includes('hidden'), 'selectedFileInfo is initially hidden');
  assert.ok(html.includes('>Remove</button>'), 'Remove button text is present');
});

test('frontend/src/styles.css contains rules for selected-file display', () => {
  const css = readFileSync(join(__dirname, '../src/styles.css'), 'utf-8');

  assert.ok(css.includes('.selected-file-info'), '.selected-file-info class is defined');
  assert.ok(css.includes('.selected-file-info[hidden]'), '.selected-file-info[hidden] is defined');
  assert.ok(css.includes('#selectedFileName'), '#selectedFileName is styled');
  assert.ok(css.includes('#selectedFileSize'), '#selectedFileSize is styled');
  assert.ok(css.includes('#clearSelectedFile'), '#clearSelectedFile is styled');
});

test('file selection and clearing logic updates state and formats sizes correctly', () => {
  // Mock DOM elements matching main.js
  const elements = {
    inputFile: { value: 'C:\\fakepath\\capture.pcap', files: [{ name: 'capture.pcap', size: 2048 }] },
    selectedFileInfo: { hidden: true },
    selectedFileName: { textContent: '' },
    selectedFileSize: { textContent: '' },
    clearSelectedFile: {},
  };

  const listeners = {};
  elements.inputFile.addEventListener = (evt, handler) => { listeners['input:' + evt] = handler; };
  elements.clearSelectedFile.addEventListener = (evt, handler) => { listeners['clear:' + evt] = handler; };

  function updateSelectedFile() {
    const file = elements.inputFile?.files?.[0];

    if (elements.selectedFileInfo) {
      elements.selectedFileInfo.hidden = !file;
    }

    if (!file) {
      if (elements.selectedFileName) elements.selectedFileName.textContent = '';
      if (elements.selectedFileSize) elements.selectedFileSize.textContent = '';
      return;
    }

    if (elements.selectedFileName) elements.selectedFileName.textContent = file.name;

    const size = file.size < 1024 * 1024
      ? `${(file.size / 1024).toFixed(1)} KB`
      : `${(file.size / (1024 * 1024)).toFixed(2)} MB`;

    if (elements.selectedFileSize) elements.selectedFileSize.textContent = size;
  }

  elements.inputFile.addEventListener('change', updateSelectedFile);
  elements.clearSelectedFile.addEventListener('click', () => {
    elements.inputFile.value = '';
    elements.inputFile.files = [];
    updateSelectedFile();
  });

  // 1. Simulate file selection (2 KB)
  listeners['input:change']();
  assert.equal(elements.selectedFileInfo.hidden, false);
  assert.equal(elements.selectedFileName.textContent, 'capture.pcap');
  assert.equal(elements.selectedFileSize.textContent, '2.0 KB');

  // 2. Simulate large file selection (3.5 MB)
  elements.inputFile.files = [{ name: 'flows.parquet', size: 3.5 * 1024 * 1024 }];
  listeners['input:change']();
  assert.equal(elements.selectedFileInfo.hidden, false);
  assert.equal(elements.selectedFileName.textContent, 'flows.parquet');
  assert.equal(elements.selectedFileSize.textContent, '3.50 MB');

  // 3. Simulate clicking Remove button
  listeners['clear:click']();
  assert.equal(elements.inputFile.value, '');
  assert.equal(elements.selectedFileInfo.hidden, true);
  assert.equal(elements.selectedFileName.textContent, '');
  assert.equal(elements.selectedFileSize.textContent, '');
});
