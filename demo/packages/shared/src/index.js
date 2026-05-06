// @exochain/shared — Database pool + WASM initialization
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let pool = null;
let wasmModule = null;
let pgModule = null;

function getPg() {
  if (!pgModule) {
    pgModule = require('pg');
  }
  return pgModule;
}

export function getPool() {
  if (!pool) {
    const { DATABASE_URL } = process.env;
    if (!DATABASE_URL || DATABASE_URL.trim() === '') {
      throw new Error('DATABASE_URL is required for the ExoChain demo shared database pool');
    }
    const pg = getPg();
    pool = new pg.Pool({
      connectionString: DATABASE_URL,
    });
  }
  return pool;
}

export function getWasm() {
  if (!wasmModule) {
    wasmModule = require('@exochain/exochain-wasm');
  }
  return wasmModule;
}

// Shared JSON response helper
export function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(data));
}

// Parse request body
export function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch (e) { reject(e); }
    });
  });
}

// Simple router
export function createRouter() {
  const routes = [];
  const router = {
    get: (path, handler) => routes.push({ method: 'GET', path, handler }),
    post: (path, handler) => routes.push({ method: 'POST', path, handler }),
    handle: async (req, res) => {
      // CORS preflight
      if (req.method === 'OPTIONS') {
        res.writeHead(204, {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        });
        return res.end();
      }

      const url = new URL(req.url, `http://${req.headers.host}`);
      for (const route of routes) {
        if (req.method === route.method && url.pathname === route.path) {
          try {
            await route.handler(req, res, url);
          } catch (e) {
            console.error(`Error in ${route.method} ${route.path}:`, e);
            json(res, 500, { error: e.message });
          }
          return;
        }
      }
      json(res, 404, { error: 'Not found' });
    },
  };
  return router;
}
