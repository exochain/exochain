'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const {
  commandBaseUploadFileFilter,
  isCommandBaseUploadAllowed,
  sanitizeCommandBaseUploadFilename,
} = require('./upload-policy');

function test(name, fn) {
  try {
    fn();
    console.log(`ok - ${name}`);
  } catch (err) {
    console.error(`not ok - ${name}`);
    console.error(err.stack || err.message);
    process.exitCode = 1;
  }
}

function file(originalname, mimetype) {
  return { fieldname: 'files', originalname, mimetype };
}

test('sanitizes uploaded names to a basename with stable filesystem-safe characters', () => {
  assert.strictEqual(
    sanitizeCommandBaseUploadFilename('../../<script>quarterly plan.pdf'),
    'script_quarterly_plan.pdf'
  );
  assert.strictEqual(sanitizeCommandBaseUploadFilename('   '), 'upload');
  assert.strictEqual(sanitizeCommandBaseUploadFilename('résumé final.md'), 'r_sum_final.md');
});

test('allows only explicit document, data, source-text, image, and archive upload types', () => {
  assert.strictEqual(isCommandBaseUploadAllowed(file('notes.md', 'text/markdown')).allowed, true);
  assert.strictEqual(isCommandBaseUploadAllowed(file('plan.pdf', 'application/pdf')).allowed, true);
  assert.strictEqual(isCommandBaseUploadAllowed(file('data.json', 'application/json')).allowed, true);
  assert.strictEqual(isCommandBaseUploadAllowed(file('review.ts', 'text/plain')).allowed, true);
  assert.strictEqual(isCommandBaseUploadAllowed(file('bundle.zip', 'application/zip')).allowed, true);
  assert.strictEqual(isCommandBaseUploadAllowed(file('diagram.png', 'image/png')).allowed, true);
});

test('rejects executable and active browser-rendered upload types', () => {
  assert.strictEqual(isCommandBaseUploadAllowed(file('installer.exe', 'application/x-msdownload')).allowed, false);
  assert.strictEqual(isCommandBaseUploadAllowed(file('deploy.sh', 'text/x-shellscript')).allowed, false);
  assert.strictEqual(isCommandBaseUploadAllowed(file('payload.html', 'text/html')).allowed, false);
  assert.strictEqual(isCommandBaseUploadAllowed(file('icon.svg', 'image/svg+xml')).allowed, false);
  assert.strictEqual(isCommandBaseUploadAllowed(file('unknown.bin', 'application/octet-stream')).allowed, false);
});

test('rejects MIME types that do not match the allowed extension category', () => {
  assert.strictEqual(isCommandBaseUploadAllowed(file('diagram.png', 'text/plain')).allowed, false);
  assert.strictEqual(isCommandBaseUploadAllowed(file('bundle.zip', 'text/plain')).allowed, false);
  assert.strictEqual(isCommandBaseUploadAllowed(file('notes.md', 'image/png')).allowed, false);
});

test('multer filter normalizes accepted original names and returns 415 for blocked files', () => {
  const accepted = file('../../review notes.md', 'text/markdown');
  let acceptedCallback;
  commandBaseUploadFileFilter({}, accepted, (err, ok) => {
    acceptedCallback = { err, ok };
  });
  assert.deepStrictEqual(acceptedCallback, { err: null, ok: true });
  assert.strictEqual(accepted.originalname, 'review_notes.md');

  const rejected = file('payload.html', 'text/html');
  let rejectedCallback;
  commandBaseUploadFileFilter({}, rejected, (err, ok) => {
    rejectedCallback = { err, ok };
  });
  assert.strictEqual(rejectedCallback.ok, false);
  assert.strictEqual(rejectedCallback.err.status, 415);
  assert.match(rejectedCallback.err.message, /Unsupported upload file type/);
});

test('server wires the upload policy into every multer upload surface', () => {
  const serverPath = path.join(__dirname, '..', 'server.js');
  const source = fs.readFileSync(serverPath, 'utf8');

  assert.match(source, /require\('\.\/lib\/upload-policy'\)/);
  assert.strictEqual((source.match(/fileFilter:\s*commandBaseUploadFileFilter/g) || []).length, 3);
  assert.strictEqual((source.match(/sanitizeCommandBaseUploadFilename\(file\.originalname\)/g) || []).length, 3);
  assert.doesNotMatch(source, /`\$\{timestamp\}_\$\{file\.originalname\}`/);
});

test('browser intake allowlists match the server active-content boundary', () => {
  const publicPath = path.join(__dirname, '..', 'public', 'app.js');
  const source = fs.readFileSync(publicPath, 'utf8');

  assert.doesNotMatch(source, /accept="[^"]*\.html/);
  assert.doesNotMatch(source, /acceptedExts\s*=\s*\[[^\]]*'\.html'/);
});
