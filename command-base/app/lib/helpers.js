'use strict';

/**
 * Shared helper functions used across all service modules.
 */

function localNow() {
  return new Date().toLocaleString('sv-SE', { timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone }).replace(' ', 'T').slice(0, 19).replace('T', ' ');
}

function escHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

module.exports = { localNow, escHtml };
