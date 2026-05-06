'use strict';

const path = require('path');

const UPLOAD_ALLOWED_EXTENSIONS = new Set([
  '.c',
  '.cpp',
  '.cs',
  '.css',
  '.csv',
  '.gif',
  '.go',
  '.h',
  '.hpp',
  '.java',
  '.jpeg',
  '.jpg',
  '.js',
  '.json',
  '.jsx',
  '.kt',
  '.log',
  '.md',
  '.markdown',
  '.mjs',
  '.pdf',
  '.png',
  '.py',
  '.rb',
  '.rs',
  '.sql',
  '.toml',
  '.ts',
  '.tsx',
  '.tsv',
  '.txt',
  '.webp',
  '.yaml',
  '.yml',
  '.zip',
]);

const UPLOAD_BLOCKED_EXTENSIONS = new Set([
  '.app',
  '.apk',
  '.bash',
  '.bat',
  '.cgi',
  '.cmd',
  '.com',
  '.dll',
  '.dylib',
  '.exe',
  '.htm',
  '.html',
  '.jar',
  '.msi',
  '.php',
  '.phtml',
  '.pl',
  '.ps1',
  '.scr',
  '.sh',
  '.so',
  '.svg',
  '.war',
  '.zsh',
]);

const UPLOAD_ALLOWED_MIME_TYPES = new Set([
  'application/json',
  'application/pdf',
  'application/zip',
  'application/x-zip-compressed',
  'image/gif',
  'image/jpeg',
  'image/png',
  'image/webp',
  'text/css',
  'text/csv',
  'text/markdown',
  'text/plain',
  'text/tab-separated-values',
  'text/x-c',
  'text/x-c++',
  'text/x-go',
  'text/x-java-source',
  'text/x-markdown',
  'text/x-python',
  'text/x-ruby',
  'text/x-rust',
]);

const UPLOAD_TEXT_MIME_TYPES = new Set([
  'application/json',
  'text/css',
  'text/csv',
  'text/markdown',
  'text/plain',
  'text/tab-separated-values',
  'text/x-c',
  'text/x-c++',
  'text/x-go',
  'text/x-java-source',
  'text/x-markdown',
  'text/x-python',
  'text/x-ruby',
  'text/x-rust',
]);

const UPLOAD_TEXT_EXTENSIONS = new Set([
  '.c',
  '.cpp',
  '.cs',
  '.css',
  '.csv',
  '.go',
  '.h',
  '.hpp',
  '.java',
  '.js',
  '.json',
  '.jsx',
  '.kt',
  '.log',
  '.md',
  '.markdown',
  '.mjs',
  '.py',
  '.rb',
  '.rs',
  '.sql',
  '.toml',
  '.ts',
  '.tsx',
  '.tsv',
  '.txt',
  '.yaml',
  '.yml',
]);

const UPLOAD_IMAGE_EXTENSIONS = new Set(['.gif', '.jpeg', '.jpg', '.png', '.webp']);
const UPLOAD_IMAGE_MIME_TYPES = new Set(['image/gif', 'image/jpeg', 'image/png', 'image/webp']);
const UPLOAD_ARCHIVE_MIME_TYPES = new Set(['application/zip', 'application/x-zip-compressed']);

const UPLOAD_BLOCKED_MIME_TYPES = new Set([
  'application/java-archive',
  'application/javascript',
  'application/octet-stream-executable',
  'application/vnd.microsoft.portable-executable',
  'application/x-dosexec',
  'application/x-executable',
  'application/x-msdownload',
  'application/x-msdos-program',
  'application/x-php',
  'application/x-sh',
  'application/x-shellscript',
  'application/xhtml+xml',
  'image/svg+xml',
  'text/html',
  'text/javascript',
  'text/x-php',
  'text/x-shellscript',
]);

function normalizeMimeType(mimetype) {
  return String(mimetype || '')
    .split(';', 1)[0]
    .trim()
    .toLowerCase();
}

function sanitizeCommandBaseUploadFilename(originalname) {
  const basename = path.basename(String(originalname || '')).trim();
  const sanitized = basename.replace(/[^a-zA-Z0-9._-]/g, '_').replace(/_+/g, '_');
  return sanitized.replace(/^[._-]+/, '') || 'upload';
}

function createUnsupportedUploadError(reason) {
  const err = new Error(`Unsupported upload file type: ${reason}`);
  err.status = 415;
  err.code = 'UNSUPPORTED_UPLOAD_TYPE';
  return err;
}

function isTextLikeMime(mimetype) {
  return mimetype.startsWith('text/');
}

function isMimeAllowedForExtension(extension, mimetype) {
  if (!mimetype) {
    return true;
  }

  if (UPLOAD_TEXT_EXTENSIONS.has(extension)) {
    return UPLOAD_TEXT_MIME_TYPES.has(mimetype) || isTextLikeMime(mimetype);
  }

  if (UPLOAD_IMAGE_EXTENSIONS.has(extension)) {
    return UPLOAD_IMAGE_MIME_TYPES.has(mimetype);
  }

  if (extension === '.pdf') {
    return mimetype === 'application/pdf';
  }

  if (extension === '.zip') {
    return UPLOAD_ARCHIVE_MIME_TYPES.has(mimetype) || mimetype === 'application/octet-stream';
  }

  return false;
}

function isCommandBaseUploadAllowed(file) {
  const sanitizedName = sanitizeCommandBaseUploadFilename(file && file.originalname);
  const extension = path.extname(sanitizedName).toLowerCase();
  const mimetype = normalizeMimeType(file && file.mimetype);

  if (!extension) {
    return { allowed: false, sanitizedName, reason: 'missing file extension' };
  }

  if (UPLOAD_BLOCKED_EXTENSIONS.has(extension)) {
    return { allowed: false, sanitizedName, reason: `blocked extension ${extension}` };
  }

  if (!UPLOAD_ALLOWED_EXTENSIONS.has(extension)) {
    return { allowed: false, sanitizedName, reason: `unsupported extension ${extension}` };
  }

  if (UPLOAD_BLOCKED_MIME_TYPES.has(mimetype)) {
    return { allowed: false, sanitizedName, reason: `blocked MIME type ${mimetype || 'unknown'}` };
  }

  if (!mimetype) {
    return { allowed: true, sanitizedName, reason: 'allowed extension with absent MIME type' };
  }

  if (isMimeAllowedForExtension(extension, mimetype)) {
    return { allowed: true, sanitizedName, reason: 'allowed extension and MIME type' };
  }

  return { allowed: false, sanitizedName, reason: `unsupported MIME type ${mimetype}` };
}

function commandBaseUploadFileFilter(req, file, cb) {
  const result = isCommandBaseUploadAllowed(file);
  if (!result.allowed) {
    cb(createUnsupportedUploadError(result.reason), false);
    return;
  }

  file.originalname = result.sanitizedName;
  cb(null, true);
}

module.exports = {
  UPLOAD_ALLOWED_EXTENSIONS,
  UPLOAD_ALLOWED_MIME_TYPES,
  UPLOAD_ARCHIVE_MIME_TYPES,
  UPLOAD_BLOCKED_EXTENSIONS,
  UPLOAD_BLOCKED_MIME_TYPES,
  UPLOAD_IMAGE_EXTENSIONS,
  UPLOAD_IMAGE_MIME_TYPES,
  UPLOAD_TEXT_EXTENSIONS,
  UPLOAD_TEXT_MIME_TYPES,
  commandBaseUploadFileFilter,
  createUnsupportedUploadError,
  isCommandBaseUploadAllowed,
  isMimeAllowedForExtension,
  sanitizeCommandBaseUploadFilename,
};
