// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// @exochain/shared — Database pool + WASM initialization
import pg from 'pg';

let pool = null;
let wasmModule = null;

export function getPool() {
  if (!pool) {
    pool = new pg.Pool({
      connectionString: process.env.DATABASE_URL || 'postgres://exochain:exochain_dev@localhost:5432/exochain',
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
