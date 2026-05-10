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

// LiveSafe API — Emergency preparedness, ICE cards, PACE network, Golden Hour, Wellness
import http from 'node:http';
import crypto from 'node:crypto';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const wasm = require('@exochain/exochain-wasm');
import pg from 'pg';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const PORT = process.env.PORT || 3011;

function json(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
  });
  res.end(JSON.stringify(data, null, 2));
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => { try { resolve(body ? JSON.parse(body) : {}); } catch(e) { reject(e); } });
  });
}

function nowMs() { return Date.now(); }

export const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': '*', 'Access-Control-Allow-Headers': 'Content-Type' });
    return res.end();
  }
  const url = new URL(req.url, `http://${req.headers.host}`);

  try {
    if (url.pathname === '/health') return json(res, 200, { status: 'ok', service: 'livesafe-api' });

    // ══════════════════════════════════════════════════════════════════
    // PROFILE
    // ══════════════════════════════════════════════════════════════════

    if (url.pathname === '/api/profile' && req.method === 'POST') {
      const { did, display_name, email, x25519_public_key_hex } = await parseBody(req);
      await pool.query(
        `INSERT INTO livesafe_profiles (did, display_name, email, x25519_public_key_hex, created_at_ms)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (did) DO UPDATE SET
           display_name = COALESCE(EXCLUDED.display_name, livesafe_profiles.display_name),
           email = COALESCE(EXCLUDED.email, livesafe_profiles.email),
           x25519_public_key_hex = COALESCE(EXCLUDED.x25519_public_key_hex, livesafe_profiles.x25519_public_key_hex)`,
        [did, display_name, email, x25519_public_key_hex, nowMs()]
      );
      return json(res, 200, { did, status: 'profile_updated' });
    }

    if (url.pathname.startsWith('/api/profile/') && req.method === 'GET') {
      const did = url.pathname.split('/api/profile/')[1];
      const { rows } = await pool.query('SELECT * FROM livesafe_profiles WHERE did = $1', [did]);
      if (rows.length === 0) return json(res, 404, { error: 'profile not found' });
      return json(res, 200, rows[0]);
    }

    // ══════════════════════════════════════════════════════════════════
    // EMERGENCY PLANS
    // ══════════════════════════════════════════════════════════════════

    if (url.pathname === '/api/plans' && req.method === 'POST') {
      const { owner_did, scenario_type, name, rally_point, go_bag_checklist, communication_plan, evacuation_routes, special_instructions, golden_hour_steps } = await parseBody(req);
      const id = crypto.randomUUID();
      const now = nowMs();
      await pool.query(
        `INSERT INTO emergency_plans (id, owner_did, scenario_type, name, rally_point, go_bag_checklist, communication_plan, evacuation_routes, special_instructions, golden_hour_steps, created_at_ms, updated_at_ms)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [id, owner_did, scenario_type, name, rally_point, JSON.stringify(go_bag_checklist || []), communication_plan, JSON.stringify(evacuation_routes || []), special_instructions, JSON.stringify(golden_hour_steps || []), now, now]
      );
      return json(res, 201, { id });
    }

    if (url.pathname.startsWith('/api/plans/') && req.method === 'GET') {
      const did = url.pathname.split('/api/plans/')[1];
      const { rows } = await pool.query('SELECT * FROM emergency_plans WHERE owner_did = $1 ORDER BY created_at_ms DESC', [did]);
      return json(res, 200, rows);
    }

    // ══════════════════════════════════════════════════════════════════
    // ICE CARDS
    // ══════════════════════════════════════════════════════════════════

    if (url.pathname === '/api/ice-card' && req.method === 'POST') {
      const body = await parseBody(req);
      const id = crypto.randomUUID();
      const qr_token = crypto.randomUUID().replace(/-/g, '');
      await pool.query(
        `INSERT INTO ice_cards (id, owner_did, full_name, date_of_birth, blood_type, allergies, medications, medical_conditions, emergency_contacts, insurance_info, organ_donor, dnr, special_instructions, qr_token, created_at_ms)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
        [id, body.owner_did, body.full_name, body.date_of_birth, body.blood_type, JSON.stringify(body.allergies || []), JSON.stringify(body.medications || []), JSON.stringify(body.medical_conditions || []), JSON.stringify(body.emergency_contacts || []), body.insurance_info, body.organ_donor || false, body.dnr || false, body.special_instructions, qr_token, nowMs()]
      );
      return json(res, 201, { id, qr_token });
    }

    if (url.pathname.startsWith('/api/ice-card/scan/') && req.method === 'POST') {
      const token = url.pathname.split('/api/ice-card/scan/')[1];
      const { responder_did } = await parseBody(req);
      const { rows } = await pool.query('SELECT * FROM ice_cards WHERE qr_token = $1 AND card_status = $2', [token, 'active']);
      if (rows.length === 0) return json(res, 404, { error: 'card not found or revoked' });

      const card = rows[0];
      const consentExpires = nowMs() + (60 * 60 * 1000); // 1 hour consent window

      // Record scan receipt
      await pool.query(
        `INSERT INTO ice_scan_receipts (id, card_id, subscriber_did, responder_did, scanned_at_ms, consent_expires_at_ms)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [crypto.randomUUID(), card.id, card.owner_did, responder_did, nowMs(), consentExpires]
      );

      return json(res, 200, { card, consent_expires_at_ms: consentExpires });
    }

    if (url.pathname.startsWith('/api/ice-card/') && req.method === 'GET') {
      const did = url.pathname.split('/api/ice-card/')[1];
      const { rows } = await pool.query('SELECT * FROM ice_cards WHERE owner_did = $1 ORDER BY created_at_ms DESC LIMIT 1', [did]);
      if (rows.length === 0) return json(res, 404, { error: 'no ICE card found' });
      return json(res, 200, rows[0]);
    }

    // ══════════════════════════════════════════════════════════════════
    // PACE NETWORK
    // ══════════════════════════════════════════════════════════════════

    if (url.pathname === '/api/pace/invite' && req.method === 'POST') {
      const { owner_did, trustee_email, trustee_name, role, relationship } = await parseBody(req);
      const token = crypto.randomUUID();
      await pool.query(
        `INSERT INTO livesafe_pace_network (owner_did, trustee_email, trustee_name, role, relationship, invitation_token, created_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [owner_did, trustee_email, trustee_name, role, relationship, token, nowMs()]
      );
      return json(res, 201, { invitation_token: token, role });
    }

    if (url.pathname === '/api/pace/accept' && req.method === 'POST') {
      const { invitation_token, trustee_did } = await parseBody(req);
      const result = await pool.query(
        `UPDATE livesafe_pace_network SET trustee_did = $1, invitation_status = 'accepted', accepted_at_ms = $2 WHERE invitation_token = $3 AND invitation_status = 'pending' RETURNING *`,
        [trustee_did, nowMs(), invitation_token]
      );
      if (result.rows.length === 0) return json(res, 404, { error: 'invitation not found' });
      return json(res, 200, { accepted: true, member: result.rows[0] });
    }

    if (url.pathname.startsWith('/api/pace/network/') && req.method === 'GET') {
      const did = url.pathname.split('/api/pace/network/')[1];
      const { rows } = await pool.query(
        `SELECT * FROM livesafe_pace_network WHERE owner_did = $1 ORDER BY CASE role WHEN 'Primary' THEN 1 WHEN 'Alternate' THEN 2 WHEN 'Contingency' THEN 3 WHEN 'Emergency' THEN 4 END`, [did]
      );
      return json(res, 200, rows);
    }

    if (url.pathname.startsWith('/api/pace/responsibilities/') && req.method === 'GET') {
      const did = url.pathname.split('/api/pace/responsibilities/')[1];
      const { rows } = await pool.query(
        `SELECT owner_did, role FROM livesafe_pace_network WHERE trustee_did = $1 AND invitation_status = 'accepted'`, [did]
      );
      return json(res, 200, { count: rows.length, networks: rows });
    }

    // ══════════════════════════════════════════════════════════════════
    // WELLNESS CHECKS
    // ══════════════════════════════════════════════════════════════════

    if (url.pathname === '/api/wellness/check-in' && req.method === 'POST') {
      const { did } = await parseBody(req);
      const id = crypto.randomUUID();
      await pool.query(
        `INSERT INTO wellness_checks (id, owner_did, status, responded_at_ms, created_at_ms) VALUES ($1,$2,'ok',$3,$4)`,
        [id, did, nowMs(), nowMs()]
      );
      return json(res, 201, { sent: true, id });
    }

    if (url.pathname.startsWith('/api/wellness/') && req.method === 'GET') {
      const did = url.pathname.split('/api/wellness/')[1];
      const { rows } = await pool.query(
        'SELECT * FROM wellness_checks WHERE owner_did = $1 ORDER BY created_at_ms DESC LIMIT 50', [did]
      );
      return json(res, 200, rows);
    }

    // ══════════════════════════════════════════════════════════════════
    // KEYS
    // ══════════════════════════════════════════════════════════════════

    if (url.pathname === '/api/keys/generate' && req.method === 'POST') {
      const keypair = wasm.wasm_generate_x25519_keypair();
      return json(res, 200, keypair);
    }

    json(res, 404, { error: 'not found', path: url.pathname });
  } catch (err) {
    console.error('LiveSafe API error:', err);
    json(res, 500, { error: err.message || 'internal server error' });
  }
});

server.listen(PORT, () => {
  console.log(`✅ LiveSafe API running on port ${PORT}`);
});
