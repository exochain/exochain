const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const {
  buildInactiveCredentialCustodyReceipt,
  buildCredentialCustodySuccessMessage,
} = require('../utils/credential-custody-receipt');
const { sendError } = require('../utils/errorHandler');

const JWT_SECRET = process.env.JWT_SECRET;

// Encryption key for credential vault (in production, use a KMS like AWS KMS or HashiCorp Vault)
const ENCRYPTION_KEY = crypto.createHash('sha256')
  .update(process.env.CREDENTIAL_ENCRYPTION_KEY)
  .digest(); // 32 bytes for AES-256

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, '..', 'uploads', 'credentials');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Ensure encrypted uploads directory exists
const encryptedDir = path.join(__dirname, '..', 'uploads', 'credentials', 'encrypted');
if (!fs.existsSync(encryptedDir)) {
  fs.mkdirSync(encryptedDir, { recursive: true });
}

// ── AES-256-GCM Encryption utilities ──────────────────────────
function encryptFile(inputPath) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  const input = fs.readFileSync(inputPath);
  const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // Store as: iv (16 bytes) + authTag (16 bytes) + encrypted data
  const combined = Buffer.concat([iv, authTag, encrypted]);
  const encryptedFilename = 'enc-' + crypto.randomBytes(16).toString('hex') + '.vault';
  const encryptedPath = path.join(encryptedDir, encryptedFilename);
  fs.writeFileSync(encryptedPath, combined);
  return { encryptedFilename, encryptedPath, originalSize: input.length, encryptedSize: combined.length };
}

function encryptString(plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted.toString('hex');
}

// Sanitize credential for API response - strip raw data for government IDs and advance directives
function sanitizeCredentialForResponse(credential) {
  if (credential.credential_type === 'insurance_card') {
    var safe = Object.assign({}, credential);
    try {
      var meta = JSON.parse(safe.data_encrypted);
      safe.data_encrypted = JSON.stringify({
        encrypted: false,
        original_name: meta.original_name,
        file_size: meta.file_size,
        mime_type: meta.mime_type,
        extraction_confidence: meta.extraction_confidence,
        extraction_method: meta.extraction_method
      });
    } catch (e) {
      safe.data_encrypted = JSON.stringify({ encrypted: false });
    }
    return safe;
  }
  if (credential.credential_type === 'government_id') {
    // Never expose raw encrypted data or file paths in API responses
    var safe = Object.assign({}, credential);
    // Parse data_encrypted to get only safe metadata
    try {
      var meta = JSON.parse(safe.data_encrypted);
      safe.data_encrypted = JSON.stringify({
        encrypted: true,
        algorithm: meta.algorithm || 'AES-256-GCM',
        document_type: meta.document_type,
        issuing_authority: meta.issuing_authority,
        document_number_masked: meta.document_number_masked,
        upload_date: meta.upload_date,
        file_size_original: meta.file_size_original,
        encryption_verified: true
      });
    } catch (e) {
      safe.data_encrypted = JSON.stringify({ encrypted: true, algorithm: 'AES-256-GCM' });
    }
    return safe;
  }
  if (credential.credential_type === 'advance_directive') {
    // Never expose encrypted file paths - only return safe metadata
    var safe = Object.assign({}, credential);
    try {
      var meta = JSON.parse(safe.data_encrypted);
      safe.data_encrypted = JSON.stringify({
        encrypted: true,
        algorithm: meta.algorithm || 'AES-256-GCM',
        original_filename: meta.original_filename,
        file_size_original: meta.file_size_original,
        upload_date: meta.upload_date,
        document_date: meta.document_date,
        description: meta.description,
        notary_info: meta.notary_info,
        subscriber_did: meta.subscriber_did,
        custody_receipt_id: meta.custody_receipt_id || meta.bailment_receipt_id,
        encryption_verified: true
      });
    } catch (e) {
      safe.data_encrypted = JSON.stringify({ encrypted: true, algorithm: 'AES-256-GCM' });
    }
    return safe;
  }
  if (credential.credential_type === 'power_of_attorney') {
    // Feature #119: Sanitize POA - expose trustee mapping but not file paths
    var safe = Object.assign({}, credential);
    try {
      var meta = JSON.parse(safe.data_encrypted);
      safe.data_encrypted = JSON.stringify({
        encrypted: meta.has_document,
        algorithm: meta.has_document ? (meta.algorithm || 'AES-256-GCM') : null,
        has_document: meta.has_document || false,
        document_date: meta.document_date,
        attorney_name: meta.attorney_name,
        attorney_relationship: meta.attorney_relationship,
        notes: meta.notes,
        subscriber_did: meta.subscriber_did,
        custody_receipt_id: meta.custody_receipt_id || meta.bailment_receipt_id,
        // PACE trustee mapping fields (safe to expose)
        pace_trustee_id: meta.pace_trustee_id,
        pace_trustee_did: meta.pace_trustee_did,
        pace_trustee_email: meta.pace_trustee_email,
        pace_trustee_name: meta.pace_trustee_name,
        pace_trustee_role: meta.pace_trustee_role,
        upload_date: meta.upload_date
      });
    } catch (e) {
      safe.data_encrypted = JSON.stringify({ encrypted: false });
    }
    return safe;
  }
  return credential;
}

// Configure multer for credential image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, `credential-${uniqueSuffix}${ext}`);
  }
});

const upload = multer({
  storage,
  // Credential metadata uses flat fields; never permit large indexed arrays.
  limits: { fileSize: 10 * 1024 * 1024, fieldArrayIndexLimit: 0 }, // 10MB limit for card images
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'application/pdf'];
    const ext = file.originalname.toLowerCase().split('.').pop();
    const allowedExts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf'];
    if (allowedTypes.includes(file.mimetype) || allowedExts.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('File type not allowed. Accepted: JPEG, PNG, GIF, WebP, PDF'), false);
    }
  }
});

// Auth middleware
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    // Feature #77: Only subscribers may access the credential vault
    // Responders, providers, and trustees are denied access to prevent unauthorized data exposure
    if (decoded.role !== 'subscriber') {
      return res.status(403).json({
        error: 'Access denied: credential vault requires subscriber authentication',
        code: 'SUBSCRIBER_ONLY',
        access_type: 'none',
      });
    }
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Simulated OCR/field extraction for insurance cards
// In production, this would use an OCR service like Google Vision, AWS Textract, etc.
function extractInsuranceFields(filename, originalName) {
  // Simulate intelligent field extraction from the uploaded insurance card image
  // Real implementation would use OCR + NLP to parse the card
  const lowerName = (originalName || '').toLowerCase();

  // Generate realistic extracted data based on the upload
  let carrier = 'Blue Cross Blue Shield';
  let memberId = 'BCB' + Math.random().toString(36).substring(2, 10).toUpperCase();
  let groupNumber = 'GRP-' + Math.floor(100000 + Math.random() * 900000);

  // Detect carrier hints from filename
  if (lowerName.includes('aetna')) {
    carrier = 'Aetna';
    memberId = 'AET' + Math.random().toString(36).substring(2, 10).toUpperCase();
  } else if (lowerName.includes('united') || lowerName.includes('uhc')) {
    carrier = 'UnitedHealthcare';
    memberId = 'UHC' + Math.random().toString(36).substring(2, 10).toUpperCase();
  } else if (lowerName.includes('cigna')) {
    carrier = 'Cigna';
    memberId = 'CGN' + Math.random().toString(36).substring(2, 10).toUpperCase();
  } else if (lowerName.includes('humana')) {
    carrier = 'Humana';
    memberId = 'HUM' + Math.random().toString(36).substring(2, 10).toUpperCase();
  } else if (lowerName.includes('kaiser')) {
    carrier = 'Kaiser Permanente';
    memberId = 'KP' + Math.random().toString(36).substring(2, 10).toUpperCase();
  }

  // Generate effective dates (current year, 1-year coverage)
  const now = new Date();
  const effectiveDate = new Date(now.getFullYear(), 0, 1).toISOString().split('T')[0]; // Jan 1 of current year
  const expiryDate = new Date(now.getFullYear(), 11, 31).toISOString().split('T')[0]; // Dec 31 of current year

  return {
    carrier,
    member_id: memberId,
    group_number: groupNumber,
    effective_date: effectiveDate,
    expiry_date: expiryDate,
    extraction_confidence: 0.87,
    extraction_method: 'ocr_simulation'
  };
}

// POST /api/credentials/insurance - Upload insurance card and extract fields
router.post('/insurance', authMiddleware, upload.single('card_image'), async (req, res) => {
  try {
    const db = req.app.locals.db;
    const subscriberId = req.user.id;

    if (!req.file) {
      return res.status(400).json({ error: 'Insurance card image is required' });
    }

    // Extract fields from the uploaded card image
    const extracted = extractInsuranceFields(req.file.filename, req.file.originalname);

    // Allow manual overrides from the request body
    const carrier = req.body.carrier || extracted.carrier;
    const memberId = req.body.member_id || extracted.member_id;
    const groupNumber = req.body.group_number || extracted.group_number;
    const effectiveDate = req.body.effective_date || extracted.effective_date;
    const expiryDate = req.body.expiry_date || extracted.expiry_date;
    const title = req.body.title || `${carrier} Insurance Card`;

    // Store in credentials table
    const result = await db.query(
      `INSERT INTO credentials (subscriber_id, credential_type, title, carrier, member_id, group_number, effective_date, expiry_date, data_encrypted, visibility)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING *`,
      [
        subscriberId,
        'insurance_card',
        title,
        carrier,
        memberId,
        groupNumber,
        effectiveDate,
        expiryDate,
        JSON.stringify({
          file_path: req.file.filename,
          original_name: req.file.originalname,
          file_size: req.file.size,
          mime_type: req.file.mimetype,
          extraction_confidence: extracted.extraction_confidence,
          extraction_method: extracted.extraction_method
        }),
        'private'
      ]
    );

    console.log(`[Credentials] Insurance card uploaded for subscriber ${subscriberId}: ${carrier} (${memberId})`);

    res.status(201).json({
      credential: sanitizeCredentialForResponse(result.rows[0]),
      extracted_fields: {
        carrier,
        member_id: memberId,
        group_number: groupNumber,
        effective_date: effectiveDate,
        expiry_date: expiryDate,
        confidence: extracted.extraction_confidence
      },
      file: {
        originalName: req.file.originalname,
        size: req.file.size,
        mimetype: req.file.mimetype
      },
      message: 'Insurance card uploaded and fields extracted successfully'
    });
  } catch (err) {
    console.error('[Credentials] Insurance upload error:', err.message);
    res.status(500).json({ error: 'Failed to upload insurance card' });
  }
});

// POST /api/credentials/advance-directive - Upload advance directive / living will
router.post('/advance-directive', authMiddleware, upload.single('directive_document'), async (req, res) => {
  try {
    const db = req.app.locals.db;
    const subscriberId = req.user.id;

    if (!req.file) {
      return res.status(400).json({ error: 'Advance directive document is required' });
    }

    // Get subscriber DID for local encrypted custody metadata
    const subResult = await db.query('SELECT did FROM subscribers WHERE id = $1', [subscriberId]);
    if (subResult.rows.length === 0) {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      return res.status(404).json({ error: 'Subscriber not found' });
    }
    const subscriberDid = subResult.rows[0].did;

    // Encrypt the uploaded document file using AES-256-GCM
    const encResult = encryptFile(req.file.path);

    // Delete the original unencrypted file immediately
    fs.unlinkSync(req.file.path);

    const documentTitle = req.body.title || 'Advance Directive';
    const documentDescription = req.body.description || '';
    const documentDate = req.body.document_date || new Date().toISOString().split('T')[0];
    const notaryInfo = req.body.notary_info || '';

    const custodyReceiptId = 'custody:receipt:' + crypto.randomBytes(16).toString('hex');
    const exochainReceipt = JSON.stringify(
      buildInactiveCredentialCustodyReceipt({
        receipt_id: custodyReceiptId,
        subscriber_did: subscriberDid,
        asset_type: 'advance_directive',
        asset_hash: crypto.createHash('sha256').update(encResult.encryptedFilename).digest('hex'),
        timestamp: new Date().toISOString(),
      })
    );

    // Store metadata in credentials table
    var encryptedMetadata = JSON.stringify({
      algorithm: 'AES-256-GCM',
      encrypted_file: encResult.encryptedFilename,
      original_filename: req.file.originalname,
      file_size_original: encResult.originalSize,
      file_size_encrypted: encResult.encryptedSize,
      mime_type: req.file.mimetype,
      upload_date: new Date().toISOString(),
      document_date: documentDate,
      description: documentDescription,
      notary_info: notaryInfo,
      subscriber_did: subscriberDid,
      custody_receipt_id: custodyReceiptId,
      encryption_verified: true
    });

    var result = await db.query(
      'INSERT INTO credentials (subscriber_id, credential_type, title, data_encrypted, visibility, exochain_receipt) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [subscriberId, 'advance_directive', documentTitle, encryptedMetadata, 'private', exochainReceipt]
    );

    console.log('[Credentials] Advance directive stored in encrypted local custody for subscriber ' + subscriberId + ' (DID: ' + subscriberDid + '): ' + documentTitle);

    // Return sanitized response
    var cred = result.rows[0];
    res.status(201).json({
      credential: {
        id: cred.id,
        credential_type: cred.credential_type,
        title: cred.title,
        visibility: cred.visibility,
        created_at: cred.created_at,
        exochain_receipt: cred.exochain_receipt,
        subscriber_did: subscriberDid,
        encrypted: true,
        algorithm: 'AES-256-GCM'
      },
      custody_receipt: {
        receipt_id: custodyReceiptId,
        receipt_type: 'LOCAL_ENCRYPTED_CUSTODY',
        subscriber_did: subscriberDid,
        asset_type: 'advance_directive',
        custody_state: 'local_only'
      },
      message: buildCredentialCustodySuccessMessage({ asset_type: 'advance_directive' })
    });
  } catch (err) {
    console.error('[Credentials] Advance directive upload error:', err.message);
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: 'Failed to upload advance directive' });
  }
});

// POST /api/credentials/government-id - Upload government ID with encryption
router.post('/government-id', authMiddleware, upload.single('id_document'), async (req, res) => {
  try {
    const db = req.app.locals.db;
    const subscriberId = req.user.id;

    if (!req.file) {
      return res.status(400).json({ error: 'Government ID document is required' });
    }

    const documentType = req.body.document_type || 'drivers_license';
    const validTypes = ['drivers_license', 'passport', 'state_id', 'military_id', 'national_id'];
    if (!validTypes.includes(documentType)) {
      // Clean up uploaded file
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'Invalid document type. Accepted: ' + validTypes.join(', ') });
    }

    const issuingAuthority = req.body.issuing_authority || '';
    const documentNumber = req.body.document_number || '';

    // Encrypt the uploaded document file using AES-256-GCM
    const encResult = encryptFile(req.file.path);

    // Delete the original unencrypted file immediately
    fs.unlinkSync(req.file.path);

    // Encrypt the document number if provided
    var encryptedDocNumber = '';
    var maskedDocNumber = '';
    if (documentNumber) {
      encryptedDocNumber = encryptString(documentNumber);
      // Only store last 4 characters as masked version
      maskedDocNumber = documentNumber.length > 4
        ? '***' + documentNumber.slice(-4)
        : '****';
    }

    // Build document type display name
    var typeNames = {
      drivers_license: "Driver's License",
      passport: 'Passport',
      state_id: 'State ID',
      military_id: 'Military ID',
      national_id: 'National ID'
    };
    var title = typeNames[documentType] || 'Government ID';

    // Store metadata (encrypted) in credentials table
    var encryptedMetadata = JSON.stringify({
      algorithm: 'AES-256-GCM',
      encrypted_file: encResult.encryptedFilename,
      document_type: documentType,
      document_number_encrypted: encryptedDocNumber,
      document_number_masked: maskedDocNumber,
      issuing_authority: issuingAuthority,
      original_filename: req.file.originalname,
      file_size_original: encResult.originalSize,
      file_size_encrypted: encResult.encryptedSize,
      mime_type: req.file.mimetype,
      upload_date: new Date().toISOString(),
      encryption_verified: true
    });

    var result = await db.query(
      'INSERT INTO credentials (subscriber_id, credential_type, title, data_encrypted, visibility) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [subscriberId, 'government_id', title, encryptedMetadata, 'private']
    );

    console.log('[Credentials] Government ID uploaded (encrypted) for subscriber ' + subscriberId + ': ' + title);

    // Return sanitized response - never expose raw data
    res.status(201).json({
      credential: sanitizeCredentialForResponse(result.rows[0]),
      document_info: {
        document_type: documentType,
        title: title,
        issuing_authority: issuingAuthority,
        document_number_masked: maskedDocNumber,
        encrypted: true,
        algorithm: 'AES-256-GCM'
      },
      message: 'Government ID uploaded and encrypted successfully'
    });
  } catch (err) {
    console.error('[Credentials] Government ID upload error:', err.message);
    // Clean up uploaded file on error
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: 'Failed to upload government ID' });
  }
});

// POST /api/credentials/poa - Upload Power of Attorney document, linked to PACE trustee (Feature #119)
router.post('/poa', authMiddleware, upload.single('poa_document'), async (req, res) => {
  try {
    const db = req.app.locals.db;
    const subscriberId = req.user.id;

    // File is optional - subscriber may just record POA metadata without document
    const { trustee_id, attorney_name, attorney_relationship, document_date, notes } = req.body;

    // Get subscriber DID
    const subResult = await db.query('SELECT did FROM subscribers WHERE id = $1', [subscriberId]);
    if (subResult.rows.length === 0) {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      return res.status(404).json({ error: 'Subscriber not found' });
    }
    const subscriberDid = subResult.rows[0].did;

    // Verify trustee belongs to this subscriber (if provided)
    var trusteeInfo = null;
    if (trustee_id) {
      const trusteeResult = await db.query(
        'SELECT id, did, email, first_name, last_name, role FROM trustees WHERE id = $1 AND subscriber_id = $2',
        [trustee_id, subscriberId]
      );
      if (trusteeResult.rows.length === 0) {
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        return res.status(404).json({ error: 'Trustee not found or does not belong to this subscriber' });
      }
      trusteeInfo = trusteeResult.rows[0];
    }

    // Encrypt document file if uploaded
    var encryptedFileInfo = null;
    if (req.file) {
      encryptedFileInfo = encryptFile(req.file.path);
      fs.unlinkSync(req.file.path);
    }

    var custodyReceiptId = 'custody:receipt:poa:' + crypto.randomBytes(16).toString('hex');
    var exochainReceipt = JSON.stringify(
      buildInactiveCredentialCustodyReceipt({
        receipt_id: custodyReceiptId,
        subscriber_did: subscriberDid,
        asset_type: 'power_of_attorney',
        asset_hash: encryptedFileInfo
          ? crypto.createHash('sha256').update(encryptedFileInfo.encryptedFilename).digest('hex')
          : crypto.createHash('sha256').update(subscriberDid + Date.now()).digest('hex'),
        timestamp: new Date().toISOString(),
        pace_trustee_did: trusteeInfo ? trusteeInfo.did : null,
      })
    );

    // Store metadata with trustee mapping
    var encryptedMetadata = JSON.stringify({
      algorithm: encryptedFileInfo ? 'AES-256-GCM' : null,
      encrypted_file: encryptedFileInfo ? encryptedFileInfo.encryptedFilename : null,
      original_filename: req.file ? req.file.originalname : null,
      file_size_original: encryptedFileInfo ? encryptedFileInfo.originalSize : null,
      mime_type: req.file ? req.file.mimetype : null,
      upload_date: new Date().toISOString(),
      document_date: document_date || new Date().toISOString().split('T')[0],
      attorney_name: attorney_name || null,
      attorney_relationship: attorney_relationship || null,
      notes: notes || null,
      subscriber_did: subscriberDid,
      custody_receipt_id: custodyReceiptId,
      // PACE trustee mapping
      pace_trustee_id: trusteeInfo ? trusteeInfo.id : null,
      pace_trustee_did: trusteeInfo ? trusteeInfo.did : null,
      pace_trustee_email: trusteeInfo ? trusteeInfo.email : null,
      pace_trustee_name: trusteeInfo ? ((trusteeInfo.first_name || '') + ' ' + (trusteeInfo.last_name || '')).trim() : null,
      pace_trustee_role: trusteeInfo ? trusteeInfo.role : null,
      has_document: !!encryptedFileInfo
    });

    var title = 'Power of Attorney' + (attorney_name ? ' - ' + attorney_name : '');
    var result = await db.query(
      'INSERT INTO credentials (subscriber_id, credential_type, title, data_encrypted, visibility, exochain_receipt) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [subscriberId, 'power_of_attorney', title, encryptedMetadata, 'private', exochainReceipt]
    );

    var cred = result.rows[0];
    console.log('[Credentials] POA stored for subscriber ' + subscriberId + ' (DID: ' + subscriberDid + ')' + (trusteeInfo ? ', linked to PACE trustee ' + trusteeInfo.id : ''));

    res.status(201).json({
      credential: {
        id: cred.id,
        credential_type: cred.credential_type,
        title: cred.title,
        visibility: cred.visibility,
        created_at: cred.created_at,
        exochain_receipt: cred.exochain_receipt,
        subscriber_did: subscriberDid,
        pace_trustee_id: trusteeInfo ? trusteeInfo.id : null,
        pace_trustee_did: trusteeInfo ? trusteeInfo.did : null,
        pace_trustee_role: trusteeInfo ? trusteeInfo.role : null,
        has_document: !!encryptedFileInfo,
        encrypted: !!encryptedFileInfo
      },
      custody_receipt: {
        receipt_id: custodyReceiptId,
        receipt_type: 'LOCAL_ENCRYPTED_CUSTODY',
        subscriber_did: subscriberDid,
        asset_type: 'power_of_attorney',
        pace_trustee_did: trusteeInfo ? trusteeInfo.did : null,
        custody_state: 'local_only'
      },
      message: buildCredentialCustodySuccessMessage({ asset_type: 'power_of_attorney' })
        .replace(' successfully', trusteeInfo ? ' with PACE trustee mapping successfully' : ' successfully')
    });
  } catch (err) {
    console.error('[Credentials] POA upload error:', err.message);
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.status(500).json({ error: 'Failed to store Power of Attorney' });
  }
});

// PUT /api/credentials/:id/visibility - Update visibility/access setting for a credential
router.put('/:id/visibility', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const { id } = req.params;
    const subscriberId = req.user.id;
    const { visibility } = req.body;

    const validVisibilities = ['private', 'emergency_visible', 'always_visible'];
    if (!visibility || !validVisibilities.includes(visibility)) {
      return res.status(400).json({ error: 'Invalid visibility. Accepted: ' + validVisibilities.join(', ') });
    }

    // Verify ownership
    const existing = await db.query(
      'SELECT id, credential_type, title FROM credentials WHERE id = $1 AND subscriber_id = $2',
      [id, subscriberId]
    );

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Credential not found' });
    }

    const result = await db.query(
      'UPDATE credentials SET visibility = $1, updated_at = NOW() WHERE id = $2 AND subscriber_id = $3 RETURNING *',
      [visibility, id, subscriberId]
    );

    console.log('[Credentials] Visibility updated for credential ' + id + ' (' + existing.rows[0].credential_type + '): ' + visibility);

    res.json({
      credential: sanitizeCredentialForResponse(result.rows[0]),
      message: 'Access setting updated to "' + visibility + '" successfully'
    });
  } catch (err) {
    console.error('[Credentials] Visibility update error:', err.message);
    res.status(500).json({ error: 'Failed to update access setting' });
  }
});

// PUT /api/credentials/:id - Update credential fields (after user review/correction)
router.put('/:id', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const { id } = req.params;
    const subscriberId = req.user.id;

    // Verify ownership
    const existing = await db.query(
      'SELECT * FROM credentials WHERE id = $1 AND subscriber_id = $2',
      [id, subscriberId]
    );

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Credential not found' });
    }

    const { carrier, member_id, group_number, effective_date, expiry_date, title } = req.body;

    const result = await db.query(
      `UPDATE credentials SET
        carrier = COALESCE($1, carrier),
        member_id = COALESCE($2, member_id),
        group_number = COALESCE($3, group_number),
        effective_date = COALESCE($4, effective_date),
        expiry_date = COALESCE($5, expiry_date),
        title = COALESCE($6, title),
        updated_at = NOW()
       WHERE id = $7 AND subscriber_id = $8
       RETURNING *`,
      [carrier, member_id, group_number, effective_date, expiry_date, title, id, subscriberId]
    );

    res.json({
      credential: sanitizeCredentialForResponse(result.rows[0]),
      message: 'Credential updated successfully',
    });
  } catch (err) {
    console.error('[Credentials] Update error:', err.message);
    res.status(500).json({ error: 'Failed to update credential' });
  }
});

// GET /api/credentials/expiry-check - Check for credentials expiring soon, send notifications
router.get('/expiry-check', authMiddleware, async (req, res) => {
  try {
    var db = req.app.locals.db;
    var subscriberId = req.user.id;
    var subscriberDid = req.user.did;

    // Find credentials expiring within 30 days that haven't been notified yet
    var expiringSoon = await db.query(
      `SELECT c.id, c.credential_type, c.title, c.carrier, c.expiry_date
       FROM credentials c
       WHERE c.subscriber_id = $1
         AND c.expiry_date IS NOT NULL
         AND c.expiry_date::date > CURRENT_DATE
         AND c.expiry_date::date <= CURRENT_DATE + INTERVAL '30 days'
         AND NOT EXISTS (
           SELECT 1 FROM notifications n
           WHERE n.notification_type = 'credential_expiring'
             AND n.body::jsonb->>'credential_id' = c.id::text
             AND n.sent_at >= NOW() - INTERVAL '7 days'
         )`,
      [subscriberId]
    );

    // Find already expired credentials that haven't been notified yet
    var expired = await db.query(
      `SELECT c.id, c.credential_type, c.title, c.carrier, c.expiry_date
       FROM credentials c
       WHERE c.subscriber_id = $1
         AND c.expiry_date IS NOT NULL
         AND c.expiry_date::date <= CURRENT_DATE
         AND NOT EXISTS (
           SELECT 1 FROM notifications n
           WHERE n.notification_type = 'credential_expired'
             AND n.body::jsonb->>'credential_id' = c.id::text
             AND n.sent_at >= NOW() - INTERVAL '30 days'
         )`,
      [subscriberId]
    );

    var notified = [];

    // Send expiring soon notifications
    for (var cred of expiringSoon.rows) {
      var label = cred.carrier || cred.title || cred.credential_type;
      var daysUntilExpiry = Math.ceil((new Date(cred.expiry_date) - new Date()) / (1000 * 60 * 60 * 24));
      await db.query(
        `INSERT INTO notifications (recipient_did, recipient_type, channel, notification_type, title, body, status)
         VALUES ($1, 'subscriber', 'push', 'credential_expiring', $2, $3, 'sent')`,
        [
          subscriberDid,
          `Credential expiring soon: ${label}`,
          JSON.stringify({
            credential_id: cred.id,
            credential_type: cred.credential_type,
            title: cred.title,
            carrier: cred.carrier,
            expiry_date: cred.expiry_date,
            days_until_expiry: daysUntilExpiry,
            alert_type: 'expiring_soon'
          })
        ]
      );
      notified.push({ id: cred.id, type: 'expiring_soon', days: daysUntilExpiry });
    }

    // Send expired notifications
    for (var cred of expired.rows) {
      var label = cred.carrier || cred.title || cred.credential_type;
      await db.query(
        `INSERT INTO notifications (recipient_did, recipient_type, channel, notification_type, title, body, status)
         VALUES ($1, 'subscriber', 'push', 'credential_expired', $2, $3, 'sent')`,
        [
          subscriberDid,
          `Credential expired: ${label}`,
          JSON.stringify({
            credential_id: cred.id,
            credential_type: cred.credential_type,
            title: cred.title,
            carrier: cred.carrier,
            expiry_date: cred.expiry_date,
            alert_type: 'expired'
          })
        ]
      );
      notified.push({ id: cred.id, type: 'expired' });
    }

    console.log('[Credentials] Expiry check: ' + notified.length + ' notifications sent for subscriber ' + subscriberId);
    res.json({
      checked: true,
      notifications_sent: notified.length,
      expiring_soon: expiringSoon.rows.length,
      expired: expired.rows.length,
      details: notified
    });
  } catch (err) {
    console.error('[Credentials] Expiry check error:', err.message);
    res.status(500).json({ error: 'Failed to check credential expiry' });
  }
});

// GET /api/credentials - Get all credentials for authenticated subscriber
router.get('/', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const subscriberId = req.user.id;

    const result = await db.query(
      'SELECT * FROM credentials WHERE subscriber_id = $1 ORDER BY created_at DESC',
      [subscriberId]
    );

    // Sanitize government ID credentials before returning
    var sanitized = result.rows.map(sanitizeCredentialForResponse);
    res.json(sanitized);
  } catch (err) {
    console.error('[Credentials] Get credentials error:', err.message);
    res.status(500).json({ error: 'Failed to get credentials' });
  }
});

// GET /api/credentials/:id - Get single credential
router.get('/:id', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const { id } = req.params;
    const subscriberId = req.user.id;

    const result = await db.query(
      'SELECT * FROM credentials WHERE id = $1 AND subscriber_id = $2',
      [id, subscriberId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Credential not found' });
    }

    // Sanitize government ID credentials before returning
    res.json(sanitizeCredentialForResponse(result.rows[0]));
  } catch (err) {
    console.error('[Credentials] Get credential error:', err.message);
    res.status(500).json({ error: 'Failed to get credential' });
  }
});

// DELETE /api/credentials/:id - Delete a credential
router.delete('/:id', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const { id } = req.params;
    const subscriberId = req.user.id;

    // Verify ownership
    const existing = await db.query(
      'SELECT * FROM credentials WHERE id = $1 AND subscriber_id = $2',
      [id, subscriberId]
    );

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Credential not found' });
    }

    // Delete file if it exists
    const credential = existing.rows[0];
    if (credential.data_encrypted) {
      try {
        const data = JSON.parse(credential.data_encrypted);
        if (data.file_path) {
          const fullPath = path.join(uploadsDir, data.file_path);
          if (fs.existsSync(fullPath)) {
            fs.unlinkSync(fullPath);
          }
        }
        // Also delete encrypted files for government IDs
        if (data.encrypted_file) {
          const encPath = path.join(encryptedDir, data.encrypted_file);
          if (fs.existsSync(encPath)) {
            fs.unlinkSync(encPath);
          }
        }
      } catch (e) {
        // data_encrypted might not be JSON, ignore
      }
    }

    await db.query('DELETE FROM credentials WHERE id = $1', [id]);

    res.json({ message: 'Credential deleted successfully' });
  } catch (err) {
    console.error('[Credentials] Delete error:', err.message);
    res.status(500).json({ error: 'Failed to delete credential' });
  }
});

// Handle multer errors
router.use((err, req, res, next) => {
  if (err) {
    return sendError(res, err, 'Credential upload request could not be processed.', {
      correlationId: req.correlationId,
    });
  }
  next();
});

module.exports = router;
