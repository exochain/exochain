// VitalLock API — E2E encrypted messaging, PACE trustees, death verification, digital assets
import http from 'node:http';
import crypto from 'node:crypto';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const wasm = require('@exochain/exochain-wasm');
import pg from 'pg';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const PORT = process.env.PORT || 3010;

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
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': '*',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    return res.end();
  }
  const url = new URL(req.url, `http://${req.headers.host}`);

  try {
    // ── Health ──
    if (url.pathname === '/health') {
      return json(res, 200, { status: 'ok', service: 'vitallock-api' });
    }

    // ══════════════════════════════════════════════════════════════════
    // MESSAGING
    // ══════════════════════════════════════════════════════════════════

    // ── Compose (Lock & Send) ──
    // Accepts either pre-encrypted envelope (from browser WASM) or plaintext (server-side encryption)
    if (url.pathname === '/api/messages/compose' && req.method === 'POST') {
      const body = await parseBody(req);

      let envelope;
      let msgId;

      if (body.envelope) {
        // Client-side encrypted — server only stores ciphertext
        envelope = body.envelope;
        msgId = envelope.id;
      } else {
        // Server-side encryption fallback
        const {
          plaintext, content_type, sender_did, recipient_did,
          sender_signing_key_hex, recipient_x25519_public_hex,
          message_id, created_physical_ms, created_logical,
          release_on_death, release_delay_hours,
        } = body;

        if (!message_id || created_physical_ms === undefined || created_logical === undefined) {
          return json(res, 400, {
            error: 'message_id, created_physical_ms, and created_logical are required for server-side encryption',
          });
        }

        envelope = wasm.wasm_encrypt_message(
          plaintext,
          JSON.stringify(content_type || 'Text'),
          sender_did,
          recipient_did,
          sender_signing_key_hex,
          recipient_x25519_public_hex,
          message_id,
          BigInt(created_physical_ms),
          created_logical,
          release_on_death || false,
          release_delay_hours || 0,
        );
        msgId = envelope.id;
      }

      await pool.query(
        `INSERT INTO encrypted_messages
         (id, sender_did, recipient_did, envelope, content_type, subject,
          release_on_death, release_delay_hours, created_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          msgId,
          body.sender_did || envelope.sender_did,
          body.recipient_did || envelope.recipient_did,
          JSON.stringify(envelope),
          body.content_type || 'Text',
          body.subject || null,
          body.release_on_death || false,
          body.release_delay_hours || 0,
          nowMs(),
        ]
      );

      return json(res, 201, { id: msgId, status: 'locked_and_sent' });
    }

    // ── Get envelope (for client-side decryption) ──
    if (url.pathname.startsWith('/api/messages/envelope/') && req.method === 'GET') {
      const msgId = url.pathname.split('/api/messages/envelope/')[1];
      const { rows } = await pool.query(
        'SELECT envelope, sender_did FROM encrypted_messages WHERE id = $1',
        [msgId]
      );
      if (rows.length === 0) return json(res, 404, { error: 'message not found' });
      return json(res, 200, { envelope: rows[0].envelope, sender_did: rows[0].sender_did });
    }

    // ── Inbox ──
    if (url.pathname.startsWith('/api/messages/inbox/') && req.method === 'GET') {
      const did = url.pathname.split('/api/messages/inbox/')[1];
      const { rows } = await pool.query(
        `SELECT id, sender_did, content_type, subject, release_on_death,
                created_at_ms, read_at_ms
         FROM encrypted_messages
         WHERE recipient_did = $1 AND deleted_by_recipient = FALSE
           AND (release_on_death = FALSE OR released = TRUE)
         ORDER BY created_at_ms DESC`,
        [did]
      );
      return json(res, 200, rows);
    }

    // ── Sent messages ──
    if (url.pathname.startsWith('/api/messages/sent/') && req.method === 'GET') {
      const did = url.pathname.split('/api/messages/sent/')[1];
      const { rows } = await pool.query(
        `SELECT id, recipient_did, content_type, subject, release_on_death,
                release_delay_hours, created_at_ms
         FROM encrypted_messages
         WHERE sender_did = $1 AND deleted_by_sender = FALSE
         ORDER BY created_at_ms DESC`,
        [did]
      );
      return json(res, 200, rows);
    }

    // ── Open (decrypt) ──
    if (url.pathname === '/api/messages/open' && req.method === 'POST') {
      const { message_id, recipient_x25519_secret_hex, sender_ed25519_public_hex } = await parseBody(req);
      const { rows } = await pool.query(
        'SELECT envelope FROM encrypted_messages WHERE id = $1',
        [message_id]
      );
      if (rows.length === 0) return json(res, 404, { error: 'message not found' });

      const result = wasm.wasm_decrypt_message(
        JSON.stringify(rows[0].envelope),
        recipient_x25519_secret_hex,
        sender_ed25519_public_hex,
      );

      // Mark as read
      await pool.query(
        'UPDATE encrypted_messages SET read_at_ms = $1 WHERE id = $2 AND read_at_ms IS NULL',
        [nowMs(), message_id]
      );

      return json(res, 200, result);
    }

    // ── Delete message ──
    if (url.pathname.startsWith('/api/messages/') && req.method === 'DELETE') {
      const parts = url.pathname.split('/');
      const msgId = parts[parts.length - 1];
      const { did, role } = await parseBody(req);

      if (role === 'sender') {
        await pool.query('UPDATE encrypted_messages SET deleted_by_sender = TRUE WHERE id = $1 AND sender_did = $2', [msgId, did]);
      } else {
        await pool.query('UPDATE encrypted_messages SET deleted_by_recipient = TRUE WHERE id = $1 AND recipient_did = $2', [msgId, did]);
      }
      return json(res, 200, { deleted: true });
    }

    // ── Afterlife messages ──
    if (url.pathname.startsWith('/api/messages/afterlife/') && req.method === 'GET') {
      const did = url.pathname.split('/api/messages/afterlife/')[1];
      const { rows } = await pool.query(
        `SELECT id, recipient_did, content_type, subject, release_delay_hours,
                released, created_at_ms
         FROM encrypted_messages
         WHERE sender_did = $1 AND release_on_death = TRUE
         ORDER BY created_at_ms DESC`,
        [did]
      );
      return json(res, 200, rows);
    }

    // ══════════════════════════════════════════════════════════════════
    // PACE NETWORK
    // ══════════════════════════════════════════════════════════════════

    // ── Invite trustee ──
    if (url.pathname === '/api/pace/invite' && req.method === 'POST') {
      const {
        owner_did, trustee_email, trustee_name, role, relationship,
        shamir_share_encrypted,
      } = await parseBody(req);

      const token = crypto.randomUUID();
      await pool.query(
        `INSERT INTO pace_network
         (owner_did, trustee_email, trustee_name, role, relationship,
          shamir_share_encrypted, invitation_token, created_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [owner_did, trustee_email, trustee_name, role, relationship,
         shamir_share_encrypted || null, token, nowMs()]
      );

      return json(res, 201, { invitation_token: token, role, trustee_email });
    }

    // ── Accept invitation ──
    if (url.pathname === '/api/pace/accept' && req.method === 'POST') {
      const { invitation_token, trustee_did } = await parseBody(req);
      const result = await pool.query(
        `UPDATE pace_network
         SET trustee_did = $1, invitation_status = 'accepted', accepted_at_ms = $2
         WHERE invitation_token = $3 AND invitation_status = 'pending'
         RETURNING *`,
        [trustee_did, nowMs(), invitation_token]
      );
      if (result.rows.length === 0) {
        return json(res, 404, { error: 'invitation not found or already accepted' });
      }
      return json(res, 200, { accepted: true, pace_member: result.rows[0] });
    }

    // ── Get PACE network ──
    if (url.pathname.startsWith('/api/pace/network/') && req.method === 'GET') {
      const did = url.pathname.split('/api/pace/network/')[1];
      const { rows } = await pool.query(
        `SELECT id, trustee_did, trustee_email, trustee_name, role,
                relationship, invitation_status, created_at_ms, accepted_at_ms
         FROM pace_network WHERE owner_did = $1
         ORDER BY CASE role
           WHEN 'Primary' THEN 1 WHEN 'Alternate' THEN 2
           WHEN 'Contingency' THEN 3 WHEN 'Emergency' THEN 4
         END`,
        [did]
      );
      return json(res, 200, rows);
    }

    // ── Get responsibilities (trustee-of) ──
    if (url.pathname.startsWith('/api/pace/responsibilities/') && req.method === 'GET') {
      const did = url.pathname.split('/api/pace/responsibilities/')[1];
      const { rows } = await pool.query(
        `SELECT pn.owner_did, pn.role, pn.relationship, u.display_name as owner_name
         FROM pace_network pn
         JOIN users u ON u.did = pn.owner_did
         WHERE pn.trustee_did = $1 AND pn.invitation_status = 'accepted'`,
        [did]
      );
      return json(res, 200, { trustee_of_count: rows.length, responsibilities: rows });
    }

    // ══════════════════════════════════════════════════════════════════
    // DEATH VERIFICATION
    // ══════════════════════════════════════════════════════════════════

    // ── Initiate death claim ──
    if (url.pathname === '/api/death/initiate' && req.method === 'POST') {
      const {
        subject_did,
        initiated_by_did,
        required_confirmations,
        authorized_trustees,
        claim_nonce_hex,
        initiator_signature_hex,
      } = await parseBody(req);

      if (!Array.isArray(authorized_trustees)) {
        return json(res, 400, { error: 'authorized_trustees must be an array' });
      }
      if (!claim_nonce_hex || !initiator_signature_hex) {
        return json(res, 400, {
          error: 'claim_nonce_hex and initiator_signature_hex are required',
        });
      }

      const state = wasm.wasm_death_verification_new(
        subject_did,
        initiated_by_did,
        required_confirmations || 3,
        JSON.stringify(authorized_trustees),
        claim_nonce_hex,
        initiator_signature_hex
      );
      const initialStatus = state.status === 'Verified' ? 'verified' : 'pending';

      const id = crypto.randomUUID();
      await pool.query(
        `INSERT INTO death_verification
         (id, subject_did, initiated_by, required_confirmations,
          trustee_confirmations, verification_state, status, created_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [id, subject_did, initiated_by_did, required_confirmations || 3,
         JSON.stringify(state.confirmations || []), JSON.stringify(state), initialStatus, nowMs()]
      );

      return json(res, 201, { id, status: initialStatus, state });
    }

    // ── Confirm death claim ──
    if (url.pathname === '/api/death/confirm' && req.method === 'POST') {
      const {
        verification_id,
        trustee_did,
        trustee_public_key_hex,
        signature_hex,
      } = await parseBody(req);

      if (!trustee_public_key_hex || !signature_hex) {
        return json(res, 400, {
          error: 'trustee_public_key_hex and signature_hex are required',
        });
      }

      const { rows } = await pool.query(
        'SELECT * FROM death_verification WHERE id = $1',
        [verification_id]
      );
      if (rows.length === 0) return json(res, 404, { error: 'verification not found' });

      const dv = rows[0];
      if (dv.status !== 'pending') {
        return json(res, 400, { error: 'verification already resolved' });
      }
      if (!dv.verification_state || !dv.verification_state.subject_did) {
        return json(res, 500, { error: 'stored verification_state is invalid' });
      }

      const result = wasm.wasm_death_verification_confirm(
        JSON.stringify(dv.verification_state),
        trustee_did,
        trustee_public_key_hex,
        signature_hex
      );

      const verified = result.verified;
      const newStatus = verified ? 'verified' : 'pending';

      await pool.query(
        `UPDATE death_verification
         SET trustee_confirmations = $1, verification_state = $2,
             status = $3, resolved_at_ms = $4
         WHERE id = $5`,
        [
          JSON.stringify(result.state.confirmations || []),
          JSON.stringify(result.state),
          newStatus,
          verified ? nowMs() : null,
          verification_id,
        ]
      );

      // If verified, release afterlife messages
      if (verified) {
        await pool.query(
          `UPDATE encrypted_messages SET released = TRUE
           WHERE sender_did = $1 AND release_on_death = TRUE AND released = FALSE`,
          [dv.subject_did]
        );
      }

      return json(res, 200, {
        verified,
        confirmations: (result.state.confirmations || []).length,
        required: dv.required_confirmations,
        afterlife_messages_released: verified,
      });
    }

    // ══════════════════════════════════════════════════════════════════
    // DIGITAL ASSETS
    // ══════════════════════════════════════════════════════════════════

    // ── Upload asset ──
    if (url.pathname === '/api/assets' && req.method === 'POST') {
      const { owner_did, asset_type, name, description, encrypted_metadata } = await parseBody(req);
      const id = crypto.randomUUID();
      await pool.query(
        `INSERT INTO digital_assets
         (id, owner_did, asset_type, name, description, encrypted_metadata, created_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [id, owner_did, asset_type, name, description || null,
         JSON.stringify(encrypted_metadata || {}), nowMs()]
      );
      return json(res, 201, { id, status: 'stored' });
    }

    // ── List assets ──
    if (url.pathname.startsWith('/api/assets/') && req.method === 'GET') {
      const parts = url.pathname.split('/');
      if (parts.length === 4) {
        const did = parts[3];
        const { rows } = await pool.query(
          'SELECT id, asset_type, name, description, file_size, beneficiary_did, created_at_ms FROM digital_assets WHERE owner_did = $1 ORDER BY created_at_ms DESC',
          [did]
        );
        return json(res, 200, rows);
      }
    }

    // ── Assign beneficiary ──
    if (url.pathname.match(/^\/api\/assets\/[^/]+\/beneficiary$/) && req.method === 'POST') {
      const assetId = url.pathname.split('/')[3];
      const { beneficiary_did } = await parseBody(req);
      await pool.query(
        'UPDATE digital_assets SET beneficiary_did = $1 WHERE id = $2',
        [beneficiary_did, assetId]
      );
      return json(res, 200, { assigned: true });
    }

    // ══════════════════════════════════════════════════════════════════
    // 0DENTITY SCORING
    // ══════════════════════════════════════════════════════════════════

    if (url.pathname.startsWith('/api/odentity/') && req.method === 'GET') {
      const did = url.pathname.split('/api/odentity/')[1];

      // Compute score from multiple factors
      const [profileResult, paceResult, responsibilitiesResult] = await Promise.all([
        pool.query('SELECT * FROM vitallock_profiles WHERE did = $1', [did]),
        pool.query(
          `SELECT role, invitation_status FROM pace_network WHERE owner_did = $1`,
          [did]
        ),
        pool.query(
          `SELECT COUNT(*) as count FROM pace_network
           WHERE trustee_did = $1 AND invitation_status = 'accepted'`,
          [did]
        ),
      ]);

      const profile = profileResult.rows[0];
      const paceMembers = paceResult.rows;
      const trusteeOfCount = parseInt(responsibilitiesResult.rows[0]?.count || '0');

      // Score components (0-100 total)
      let score = 0;

      // DID registration (0-15)
      if (profile) score += 15;

      // PACE network health (0-25)
      const acceptedPace = paceMembers.filter(m => m.invitation_status === 'accepted').length;
      score += Math.min(25, Math.round((acceptedPace / 4) * 25));

      // Shamir shard distribution (0-20)
      const shardsDistributed = paceMembers.filter(
        m => m.invitation_status === 'accepted'
      ).length;
      score += Math.min(20, shardsDistributed * 5);

      // Account completeness (0-15)
      if (profile?.onboarding_complete) score += 10;
      if (profile?.x25519_public_key_hex) score += 5;

      // Trustee-of-others (0-15)
      score += Math.min(15, trusteeOfCount * 5);

      // Account age bonus (0-10)
      if (profile?.created_at_ms) {
        const ageMs = nowMs() - profile.created_at_ms;
        const ageDays = ageMs / (1000 * 60 * 60 * 24);
        score += Math.min(10, Math.round(ageDays / 3));
      }

      // Update stored score
      if (profile) {
        await pool.query(
          'UPDATE vitallock_profiles SET odentity_score = $1 WHERE did = $2',
          [score, did]
        );
      }

      return json(res, 200, {
        did,
        score,
        breakdown: {
          did_registration: profile ? 15 : 0,
          pace_network: Math.min(25, Math.round((acceptedPace / 4) * 25)),
          shamir_shards: Math.min(20, shardsDistributed * 5),
          account_completeness: (profile?.onboarding_complete ? 10 : 0) + (profile?.x25519_public_key_hex ? 5 : 0),
          trustee_of_others: Math.min(15, trusteeOfCount * 5),
          account_age: profile?.created_at_ms ? Math.min(10, Math.round((nowMs() - profile.created_at_ms) / (1000 * 60 * 60 * 24 * 3))) : 0,
        },
      });
    }

    // ══════════════════════════════════════════════════════════════════
    // FAMILY MEMBERS
    // ══════════════════════════════════════════════════════════════════

    // ── Invite family member ──
    if (url.pathname === '/api/family/invite' && req.method === 'POST') {
      const { owner_did, member_name, member_email, relationship, access_level } = await parseBody(req);
      await pool.query(
        `INSERT INTO family_members
         (owner_did, member_name, member_email, relationship, access_level, invited_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [owner_did, member_name, member_email, relationship, access_level || 'view', nowMs()]
      );
      return json(res, 201, { invited: true });
    }

    // ── List family members ──
    if (url.pathname.startsWith('/api/family/') && req.method === 'GET') {
      const did = url.pathname.split('/api/family/')[1];
      const { rows } = await pool.query(
        'SELECT * FROM family_members WHERE owner_did = $1 ORDER BY invited_at_ms DESC',
        [did]
      );
      return json(res, 200, rows);
    }

    // ══════════════════════════════════════════════════════════════════
    // TEMPLATES
    // ══════════════════════════════════════════════════════════════════

    if (url.pathname === '/api/templates' && req.method === 'GET') {
      const did = url.searchParams.get('did') || 'system';
      const { rows } = await pool.query(
        `SELECT * FROM message_templates
         WHERE owner_did = $1 OR is_system = TRUE
         ORDER BY is_system DESC, name ASC`,
        [did]
      );
      return json(res, 200, rows);
    }

    // ══════════════════════════════════════════════════════════════════
    // PROFILE
    // ══════════════════════════════════════════════════════════════════

    // ── Create/update profile ──
    if (url.pathname === '/api/profile' && req.method === 'POST') {
      const { did, display_name, x25519_public_key_hex } = await parseBody(req);
      await pool.query(
        `INSERT INTO vitallock_profiles (did, display_name, x25519_public_key_hex, created_at_ms)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (did) DO UPDATE SET
           display_name = COALESCE(EXCLUDED.display_name, vitallock_profiles.display_name),
           x25519_public_key_hex = COALESCE(EXCLUDED.x25519_public_key_hex, vitallock_profiles.x25519_public_key_hex)`,
        [did, display_name || null, x25519_public_key_hex || null, nowMs()]
      );
      return json(res, 200, { did, status: 'profile_updated' });
    }

    // ── Get profile ──
    if (url.pathname.startsWith('/api/profile/') && req.method === 'GET') {
      const did = url.pathname.split('/api/profile/')[1];
      const { rows } = await pool.query(
        'SELECT * FROM vitallock_profiles WHERE did = $1',
        [did]
      );
      if (rows.length === 0) return json(res, 404, { error: 'profile not found' });
      return json(res, 200, rows[0]);
    }

    // ── X25519 Key Generation ──
    if (url.pathname === '/api/keys/generate' && req.method === 'POST') {
      const keypair = wasm.wasm_generate_x25519_keypair();
      return json(res, 200, keypair);
    }

    // 404
    json(res, 404, { error: 'not found', path: url.pathname });
  } catch (err) {
    console.error('VitalLock API error:', err);
    json(res, 500, { error: err.message || 'internal server error' });
  }
});

server.listen(PORT, () => {
  console.log(`✅ VitalLock API running on port ${PORT}`);
});
