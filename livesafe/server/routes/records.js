const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const PDFDocument = require('pdfkit');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { buildInactiveDeletionAuditMetadata } = require('../utils/deletion-audit-metadata');
const { sendError } = require('../utils/errorHandler');
const { createRecordParseFailureMetadata } = require('../utils/record-extracted-data');
const {
  buildPublicMedicalRecordDeletionAcknowledgement,
  buildPublicMedicalRecordEncryptionStatusResponse,
  buildPublicMedicalRecordListResponse,
  buildPublicMedicalRecordResponse,
  buildPublicMedicalRecordVersionEnvelope,
  buildPublicMedicalRecordVersionListResponse,
} = require('../utils/medical-record-response');
const {
  buildPublicClinicalNoteCreateAcknowledgement,
  buildPublicClinicalNoteListEnvelope,
  buildPublicClinicalNoteListResponse,
  buildPublicClinicalNoteMutationAcknowledgement,
  buildPublicClinicalNoteResponse,
} = require('../utils/clinical-note-response');
const { buildPublicRecordRequestResponse } = require('../utils/record-request-response');
const {
  buildPublicRecordProviderListResponse,
} = require('../utils/record-provider-response');

const JWT_SECRET = process.env.JWT_SECRET;

// ─── C-CDA XML Parser ───────────────────────────────────────────────────────
// Extracts key clinical data from C-CDA (Consolidated Clinical Document Architecture) XML
function parseCCDA(xmlContent) {
  const extracted = {
    format: 'C-CDA',
    parsed_at: new Date().toISOString(),
    patient: {},
    allergies: [],
    medications: [],
    problems: [],
    results: [],
    vital_signs: [],
    immunizations: [],
  };

  try {
    // Helper: extract text between tags (simple regex, handles common C-CDA patterns)
    function getTagContent(xml, tag) {
      const re = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i');
      const m = xml.match(re);
      return m ? m[1].replace(/<[^>]+>/g, '').trim() : null;
    }

    function getAttr(xml, tag, attr) {
      const re = new RegExp(`<${tag}[^>]*\\s${attr}="([^"]*)"`, 'i');
      const m = xml.match(re);
      return m ? m[1] : null;
    }

    function getAllMatches(xml, pattern) {
      const results = [];
      let m;
      const re = new RegExp(pattern, 'gi');
      while ((m = re.exec(xml)) !== null) {
        results.push(m[1] || m[0]);
      }
      return results;
    }

    // Extract patient demographics
    const patientRoleMatch = xmlContent.match(/<patientRole[\s\S]*?<\/patientRole>/i);
    if (patientRoleMatch) {
      const prXml = patientRoleMatch[0];

      // Patient name
      const nameMatch = prXml.match(/<name[\s>][\s\S]*?<\/name>/i);
      if (nameMatch) {
        const given = getTagContent(nameMatch[0], 'given');
        const family = getTagContent(nameMatch[0], 'family');
        if (given || family) {
          extracted.patient.name = [given, family].filter(Boolean).join(' ');
        }
      }

      // Date of birth
      const dobMatch = prXml.match(/<birthTime[^>]*value="(\d{4})(\d{2})?(\d{2})?"/i);
      if (dobMatch) {
        const y = dobMatch[1];
        const m2 = dobMatch[2] || '01';
        const d = dobMatch[3] || '01';
        extracted.patient.dob = `${y}-${m2}-${d}`;
      }

      // Gender
      const genderMatch = prXml.match(/<administrativeGenderCode[^>]*code="([^"]+)"/i);
      if (genderMatch) {
        const code = genderMatch[1];
        extracted.patient.gender = code === 'M' ? 'Male' : code === 'F' ? 'Female' : code;
      }

      // Address
      const addrMatch = prXml.match(/<addr[\s>][\s\S]*?<\/addr>/i);
      if (addrMatch) {
        const street = getTagContent(addrMatch[0], 'streetAddressLine');
        const city = getTagContent(addrMatch[0], 'city');
        const state = getTagContent(addrMatch[0], 'state');
        const zip = getTagContent(addrMatch[0], 'postalCode');
        const parts = [street, city, state, zip].filter(Boolean);
        if (parts.length > 0) extracted.patient.address = parts.join(', ');
      }
    }

    // Extract document title
    const titleMatch = xmlContent.match(/<title>([^<]+)<\/title>/i);
    if (titleMatch) extracted.document_title = titleMatch[1].trim();

    // Extract effective time
    const effectiveMatch = xmlContent.match(/<effectiveTime[^>]*value="(\d{4})(\d{2})?(\d{2})?"/i);
    if (effectiveMatch) {
      const y = effectiveMatch[1];
      const mo = effectiveMatch[2] || '01';
      const day = effectiveMatch[3] || '01';
      extracted.document_date = `${y}-${mo}-${day}`;
    }

    // Helper: find section by template ID or code
    function findSections(xml, templateId, sectionCode) {
      const sections = [];
      // Try by templateId
      if (templateId) {
        const re = new RegExp(
          `<section>[\\s\\S]*?<templateId[^>]*root="${templateId.replace(/\./g, '\\.')}[^"]*"[\\s\\S]*?<\\/section>`,
          'gi'
        );
        let m;
        while ((m = re.exec(xml)) !== null) sections.push(m[0]);
      }
      // Try by code
      if (sectionCode && sections.length === 0) {
        const re = new RegExp(
          `<section>[\\s\\S]*?<code[^>]*code="${sectionCode}"[\\s\\S]*?<\\/section>`,
          'gi'
        );
        let m;
        while ((m = re.exec(xml)) !== null) sections.push(m[0]);
      }
      return sections;
    }

    // Extract allergies (SNOMED template 2.16.840.1.113883.10.20.22.2.6.1)
    const allergySections = findSections(xmlContent, '2.16.840.1.113883.10.20.22.2.6', '48765-2');
    for (const section of allergySections) {
      // Find allergy entries
      const entryMatches = section.match(/<entry[\s\S]*?<\/entry>/gi) || [];
      for (const entry of entryMatches) {
        const substanceMatch = entry.match(/<participant[\s\S]*?<\/participant>/i);
        let substance = null;
        if (substanceMatch) {
          substance = getAttr(substanceMatch[0], 'code', 'displayName');
          if (!substance) substance = getTagContent(substanceMatch[0], 'originalText');
        }
        if (!substance) {
          substance = getAttr(entry, 'code', 'displayName') || getTagContent(entry, 'originalText');
        }

        // Reaction
        const reactionMatch = entry.match(/<value[^>]*displayName="([^"]+)"/i);
        const reaction = reactionMatch ? reactionMatch[1] : null;

        // Status
        const statusMatch = entry.match(/<statusCode[^>]*code="([^"]+)"/i);
        const status = statusMatch ? statusMatch[1] : 'active';

        if (substance) {
          extracted.allergies.push({ substance, reaction, status });
        }
      }
    }

    // Extract medications (template 2.16.840.1.113883.10.20.22.2.1)
    const medSections = findSections(xmlContent, '2.16.840.1.113883.10.20.22.2.1', '10160-0');
    for (const section of medSections) {
      const entryMatches = section.match(/<entry[\s\S]*?<\/entry>/gi) || [];
      for (const entry of entryMatches) {
        let medName = getAttr(entry, 'manufacturedMaterial', 'displayName');
        if (!medName) medName = getAttr(entry, 'code', 'displayName');
        if (!medName) {
          const origMatch = entry.match(/<originalText>([^<]+)<\/originalText>/i);
          if (origMatch) medName = origMatch[1].trim();
        }

        const doseMatch = entry.match(/<doseQuantity[^>]*value="([^"]+)"[^>]*unit="([^"]+)"/i);
        const dose = doseMatch ? `${doseMatch[1]} ${doseMatch[2]}` : null;

        const routeMatch = entry.match(/<routeCode[^>]*displayName="([^"]+)"/i);
        const route = routeMatch ? routeMatch[1] : null;

        if (medName) {
          extracted.medications.push({ name: medName, dose, route });
        }
      }
    }

    // Extract problems/conditions (template 2.16.840.1.113883.10.20.22.2.5)
    const problemSections = findSections(xmlContent, '2.16.840.1.113883.10.20.22.2.5', '11450-4');
    for (const section of problemSections) {
      const entryMatches = section.match(/<entry[\s\S]*?<\/entry>/gi) || [];
      for (const entry of entryMatches) {
        const codeMatch = entry.match(/<value[^>]*(?:displayName|code)="([^"]+)"[^>]*(?:displayName="([^"]+)")?/i);
        let condition = null;
        if (codeMatch) {
          condition = codeMatch[2] || codeMatch[1];
        }
        if (!condition) {
          const origMatch = entry.match(/<originalText>([^<]+)<\/originalText>/i);
          if (origMatch) condition = origMatch[1].trim();
        }

        // Onset date
        const onsetMatch = entry.match(/<effectiveTime>[\s\S]*?<low[^>]*value="(\d{4})(\d{2})?(\d{2})?"/i);
        let onset = null;
        if (onsetMatch) {
          onset = `${onsetMatch[1]}-${onsetMatch[2] || '01'}-${onsetMatch[3] || '01'}`;
        }

        if (condition) {
          extracted.problems.push({ condition, onset });
        }
      }
    }

    // Extract results/labs (template 2.16.840.1.113883.10.20.22.2.3)
    const resultSections = findSections(xmlContent, '2.16.840.1.113883.10.20.22.2.3', '30954-2');
    for (const section of resultSections) {
      const orgMatches = section.match(/<organizer[\s\S]*?<\/organizer>/gi) || [];
      for (const org of orgMatches) {
        const panelName = getAttr(org, 'code', 'displayName');
        const componentMatches = org.match(/<component[\s\S]*?<\/component>/gi) || [];
        for (const comp of componentMatches) {
          const testName = getAttr(comp, 'code', 'displayName');
          const valueMatch = comp.match(/<value[^>]*value="([^"]+)"[^>]*unit="([^"]+)"/i);
          const val = valueMatch ? `${valueMatch[1]} ${valueMatch[2]}` : null;
          const interpMatch = comp.match(/<interpretationCode[^>]*displayName="([^"]+)"/i);
          const interp = interpMatch ? interpMatch[1] : null;

          if (testName) {
            extracted.results.push({ panel: panelName, test: testName, value: val, interpretation: interp });
          }
        }
      }
    }

    // Also extract from text/narrative sections (simpler fallback)
    // This handles C-CDA documents where structured data isn't in entries
    if (extracted.allergies.length === 0 && extracted.medications.length === 0) {
      // Try to extract displayName values from observation codes
      const codeDisplayMatches = xmlContent.match(/displayName="([^"]+)"/gi) || [];
      const displayNames = codeDisplayMatches.map(m => m.match(/displayName="([^"]+)"/i)?.[1]).filter(Boolean);
      if (displayNames.length > 0) {
        extracted.display_names_found = displayNames.slice(0, 10); // Top 10 for reference
      }
    }

    // Summary counts
    extracted.summary = {
      allergies_count: extracted.allergies.length,
      medications_count: extracted.medications.length,
      problems_count: extracted.problems.length,
      results_count: extracted.results.length,
    };

  } catch (_parseErr) {
    Object.assign(
      extracted,
      createRecordParseFailureMetadata({
        format: extracted.format,
        stage: 'ccda_parse',
      })
    );
  }

  return extracted;
}

// Detect if file is C-CDA XML
function isCCDA(content, mimetype, filename) {
  if (typeof content === 'string') {
    return content.includes('ClinicalDocument') &&
           (content.includes('urn:hl7-org:v3') || content.includes('2.16.840.1.113883'));
  }
  return false;
}

// ─── FHIR R4 JSON Parser ─────────────────────────────────────────────────────
// Detects and extracts structured data from FHIR R4 JSON resources/bundles

function isFHIR(content) {
  try {
    const parsed = typeof content === 'string' ? JSON.parse(content) : content;
    return typeof parsed === 'object' && parsed !== null && typeof parsed.resourceType === 'string';
  } catch {
    return false;
  }
}

function parseFHIR(jsonContent) {
  const extracted = {
    format: 'FHIR R4',
    parsed_at: new Date().toISOString(),
    patient: {},
    allergies: [],
    medications: [],
    problems: [],
    results: [],
    vital_signs: [],
    immunizations: [],
  };

  try {
    const root = typeof jsonContent === 'string' ? JSON.parse(jsonContent) : jsonContent;

    // Helper: process a single FHIR resource
    function processResource(resource) {
      if (!resource || !resource.resourceType) return;

      switch (resource.resourceType) {
        case 'Patient': {
          const name = resource.name && resource.name[0];
          if (name) {
            const given = Array.isArray(name.given) ? name.given.join(' ') : (name.given || '');
            const family = name.family || '';
            extracted.patient.name = [given, family].filter(Boolean).join(' ') || undefined;
          }
          if (resource.birthDate) extracted.patient.dob = resource.birthDate;
          if (resource.gender) extracted.patient.gender = resource.gender.charAt(0).toUpperCase() + resource.gender.slice(1);
          if (resource.address && resource.address[0]) {
            const addr = resource.address[0];
            const line = Array.isArray(addr.line) ? addr.line.join(', ') : (addr.line || '');
            const parts = [line, addr.city, addr.state, addr.postalCode].filter(Boolean);
            if (parts.length) extracted.patient.address = parts.join(', ');
          }
          break;
        }
        case 'AllergyIntolerance': {
          const substance = resource.code?.text ||
            (resource.code?.coding && resource.code.coding[0]?.display) ||
            (resource.reaction && resource.reaction[0]?.substance?.text) || 'Unknown';
          const severity = resource.reaction && resource.reaction[0]?.severity;
          extracted.allergies.push({ substance, severity: severity || null });
          break;
        }
        case 'MedicationRequest':
        case 'MedicationStatement': {
          const medCode = resource.medicationCodeableConcept || resource.medication?.CodeableConcept;
          const name = medCode?.text || (medCode?.coding && medCode.coding[0]?.display) || 'Unknown medication';
          const dose = resource.dosageInstruction && resource.dosageInstruction[0]?.text;
          extracted.medications.push({ name, dose: dose || null });
          break;
        }
        case 'Condition': {
          const condition = resource.code?.text ||
            (resource.code?.coding && resource.code.coding[0]?.display) || 'Unknown condition';
          const status = resource.clinicalStatus?.coding?.[0]?.code || resource.clinicalStatus?.text;
          extracted.problems.push({ condition, status: status || null });
          break;
        }
        case 'Observation': {
          const code = resource.code?.text || (resource.code?.coding && resource.code.coding[0]?.display) || 'Unknown';
          const value = resource.valueQuantity
            ? `${resource.valueQuantity.value} ${resource.valueQuantity.unit || ''}`.trim()
            : (resource.valueString || resource.valueCodeableConcept?.text || null);
          extracted.results.push({ test: code, value: value || null });
          break;
        }
        case 'Immunization': {
          const vaccine = resource.vaccineCode?.text ||
            (resource.vaccineCode?.coding && resource.vaccineCode.coding[0]?.display) || 'Unknown vaccine';
          const date = resource.occurrenceDateTime || resource.occurrenceString;
          extracted.immunizations.push({ vaccine, date: date || null });
          break;
        }
        case 'DocumentReference':
        case 'DiagnosticReport': {
          if (!extracted.document_title) {
            extracted.document_title = resource.description || resource.type?.text || resource.resourceType;
          }
          break;
        }
      }
    }

    if (root.resourceType === 'Bundle') {
      // FHIR R4 Bundle: process all entries
      extracted.bundle_type = root.type || null;
      extracted.resource_type = 'Bundle';
      if (Array.isArray(root.entry)) {
        root.entry.forEach(entry => {
          if (entry.resource) processResource(entry.resource);
        });
      }
    } else {
      // Single resource
      extracted.resource_type = root.resourceType;
      processResource(root);
    }

    // Build summary
    extracted.summary = {
      allergies_count: extracted.allergies.length,
      medications_count: extracted.medications.length,
      problems_count: extracted.problems.length,
      results_count: extracted.results.length,
      immunizations_count: extracted.immunizations.length,
    };

  } catch (_err) {
    Object.assign(
      extracted,
      createRecordParseFailureMetadata({
        format: extracted.format,
        stage: 'fhir_parse',
      })
    );
  }

  return extracted;
}
// ────────────────────────────────────────────────────────────────────────────

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Ensure letters directory exists
const lettersDir = path.join(__dirname, '..', 'letters');
if (!fs.existsSync(lettersDir)) {
  fs.mkdirSync(lettersDir, { recursive: true });
}

// ─── Record Encryption Utilities (Feature #92) ──────────────────────────────
const RECORD_ENCRYPTION_SERVER_SECRET = process.env.RECORD_ENCRYPTION_SECRET;

/**
 * Get or create a subscriber's record encryption key.
 * Uses AES-256-GCM. The key is derived from subscriber DID + server secret via PBKDF2.
 * Stored in subscribers.record_encryption_key as hex string.
 */
async function getOrCreateSubscriberEncryptionKey(db, subscriberId, subscriberDid) {
  // Ensure column exists
  await db.query(`ALTER TABLE subscribers ADD COLUMN IF NOT EXISTS record_encryption_key TEXT`).catch(() => {});

  const row = await db.query('SELECT record_encryption_key, did FROM subscribers WHERE id = $1', [subscriberId]);
  if (row.rows.length === 0) throw new Error('Subscriber not found');

  const sub = row.rows[0];
  if (sub.record_encryption_key) {
    return Buffer.from(sub.record_encryption_key, 'hex');
  }

  // Derive key from subscriber DID + server secret
  const did = sub.did || subscriberDid || `sub-${subscriberId}`;
  const keyMaterial = crypto.pbkdf2Sync(
    did + RECORD_ENCRYPTION_SERVER_SECRET,
    did,  // salt = DID
    100000,
    32,
    'sha256'
  );

  // Store the key
  await db.query('UPDATE subscribers SET record_encryption_key = $1 WHERE id = $2', [keyMaterial.toString('hex'), subscriberId]);
  console.log(`[Records] Generated encryption key for subscriber ${subscriberId}`);
  return keyMaterial;
}

/**
 * Encrypt file in-place using AES-256-GCM.
 * Format: [4 bytes IV length][IV][16 bytes auth tag][encrypted content]
 * Returns: { encrypted: true, algorithm: 'AES-256-GCM', keyId: subscriberId }
 */
function encryptFile(filePath, encryptionKey) {
  const plaintext = fs.readFileSync(filePath);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag(); // 16 bytes

  // Store: 4-byte IV length header + IV + authTag + encrypted content
  const ivLength = Buffer.allocUnsafe(4);
  ivLength.writeUInt32BE(iv.length);
  const output = Buffer.concat([ivLength, iv, authTag, encrypted]);
  fs.writeFileSync(filePath, output);
  return { encrypted: true, algorithm: 'AES-256-GCM', iv_length: iv.length, auth_tag_length: authTag.length };
}

/**
 * Decrypt file content from encrypted format.
 * Returns plaintext Buffer.
 */
function decryptFile(filePath, encryptionKey) {
  const data = fs.readFileSync(filePath);
  const ivLength = data.readUInt32BE(0);
  const iv = data.slice(4, 4 + ivLength);
  const authTag = data.slice(4 + ivLength, 4 + ivLength + 16);
  const encryptedContent = data.slice(4 + ivLength + 16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encryptedContent), decipher.final()]);
}
// ────────────────────────────────────────────────────────────────────────────

// Generate HIPAA Right of Access request letter PDF
function generateHIPAALetter(subscriberInfo, providerInfo, requestId) {
  return new Promise((resolve, reject) => {
    const filename = `hipaa-request-${requestId}-${Date.now()}.pdf`;
    const filePath = path.join(lettersDir, filename);
    const doc = new PDFDocument({ margin: 72 });
    const stream = fs.createWriteStream(filePath);

    doc.pipe(stream);

    const today = new Date();
    const dateStr = today.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

    // Header
    doc.fontSize(20).font('Helvetica-Bold').text('HIPAA Right of Access Request', { align: 'center' });
    doc.moveDown(0.5);
    doc.fontSize(10).font('Helvetica').fillColor('#666666').text('45 CFR 164.524 — Patient Right of Access to Protected Health Information', { align: 'center' });
    doc.moveDown(0.3);

    // Divider line
    doc.moveTo(72, doc.y).lineTo(540, doc.y).stroke('#cccccc');
    doc.moveDown(1);

    // Date
    doc.fillColor('#000000').fontSize(11).font('Helvetica').text(`Date: ${dateStr}`);
    doc.moveDown(1);

    // Provider address block
    doc.font('Helvetica-Bold').text('TO:');
    doc.font('Helvetica');
    doc.text(providerInfo.name || 'Healthcare Provider');
    if (providerInfo.npi) {
      doc.text(`NPI: ${providerInfo.npi}`);
    }
    if (providerInfo.address) {
      doc.text(providerInfo.address);
    }
    doc.moveDown(1);

    // From block
    doc.font('Helvetica-Bold').text('FROM:');
    doc.font('Helvetica');
    const subscriberName = [subscriberInfo.first_name, subscriberInfo.last_name].filter(Boolean).join(' ') || 'Subscriber';
    doc.text(subscriberName);
    doc.text(`Email: ${subscriberInfo.email || 'N/A'}`);
    if (subscriberInfo.did) {
      doc.text(`DID: ${subscriberInfo.did}`);
    }
    doc.moveDown(1);

    // Subject line
    doc.font('Helvetica-Bold').text('RE: Request for Access to Protected Health Information (PHI)');
    doc.moveDown(1);

    // Divider line
    doc.moveTo(72, doc.y).lineTo(540, doc.y).stroke('#cccccc');
    doc.moveDown(1);

    // Body text
    doc.font('Helvetica').fontSize(11);
    doc.text('Dear Records Custodian,', { continued: false });
    doc.moveDown(0.5);

    doc.text(
      `I, ${subscriberName}, am writing to exercise my right to access my protected health information (PHI) ` +
      `as guaranteed under the Health Insurance Portability and Accountability Act of 1996 (HIPAA), ` +
      `specifically 45 CFR § 164.524 — Access of Individuals to Protected Health Information.`,
      { lineGap: 3 }
    );
    doc.moveDown(0.5);

    doc.text(
      'Under this federal regulation, covered entities are required to provide individuals with access ' +
      'to their protected health information maintained in a designated record set. I hereby request ' +
      'a complete copy of all medical records, test results, treatment notes, imaging reports, and any ' +
      'other protected health information pertaining to my care at your facility.',
      { lineGap: 3 }
    );
    doc.moveDown(0.5);

    doc.font('Helvetica-Bold').text('Records Requested:');
    doc.font('Helvetica');
    const recordTypes = [
      'Medical history and physical examination records',
      'Laboratory and diagnostic test results',
      'Imaging reports (X-ray, MRI, CT, ultrasound)',
      'Treatment plans and clinical notes',
      'Prescription and medication records',
      'Surgical and procedure reports',
      'Discharge summaries',
      'Billing and insurance records related to my care'
    ];
    recordTypes.forEach(type => {
      doc.text(`  • ${type}`, { indent: 20 });
    });
    doc.moveDown(0.5);

    doc.font('Helvetica-Bold').text('Legal Obligations:');
    doc.font('Helvetica');
    doc.text(
      'Under 45 CFR § 164.524(b), you are required to respond to this request within 30 days of receipt. ' +
      'You may charge a reasonable, cost-based fee for providing copies, but may not deny access based ' +
      'on payment. If you are unable to fulfill this request within 30 days, you may extend the deadline ' +
      'by an additional 30 days with written notice.',
      { lineGap: 3 }
    );
    doc.moveDown(0.5);

    doc.text(
      'Please provide the records in electronic format if available. I authorize the transmission of ' +
      'these records through the LiveSafe.ai secure health identity platform.',
      { lineGap: 3 }
    );
    doc.moveDown(1);

    // Signature block
    doc.text('Sincerely,');
    doc.moveDown(1.5);

    // Signature line
    doc.moveTo(72, doc.y).lineTo(300, doc.y).stroke('#000000');
    doc.moveDown(0.3);
    doc.font('Helvetica-Bold').text(subscriberName);
    doc.font('Helvetica').text(`Date: ${dateStr}`);
    if (subscriberInfo.date_of_birth) {
      doc.text(`Date of Birth: ${new Date(subscriberInfo.date_of_birth).toLocaleDateString('en-US')}`);
    }

    doc.moveDown(1.5);

    // Footer
    doc.fontSize(8).fillColor('#999999');
    doc.text('This document was generated by LiveSafe.ai — a patient-sovereign health identity platform built on EXOCHAIN.', { align: 'center' });
    doc.text(`Request ID: ${requestId} | Generated: ${today.toISOString()}`, { align: 'center' });

    doc.end();

    stream.on('finish', () => {
      resolve({ filename, filePath });
    });
    stream.on('error', (err) => {
      reject(err);
    });
  });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, `record-${uniqueSuffix}${ext}`);
  }
});

const upload = multer({
  storage,
  // Record metadata uses flat fields; never permit large indexed arrays.
  limits: { fileSize: 50 * 1024 * 1024, fieldArrayIndexLimit: 0 }, // 50MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'application/pdf',
      'image/jpeg',
      'image/png',
      'image/gif',
      'text/plain',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/dicom',
      'application/octet-stream',
      'application/json',
      'application/xml',
      'text/xml',
      'application/fhir+json',
      'application/cda+xml'
    ];
    // Also accept by file extension for JSON/XML (FHIR, C-CDA)
    const ext = file.originalname.toLowerCase().split('.').pop();
    const allowedExts = ['pdf', 'jpg', 'jpeg', 'png', 'gif', 'txt', 'doc', 'docx', 'json', 'xml'];
    if (allowedTypes.includes(file.mimetype) || allowedExts.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('File type not allowed. Accepted: PDF, JPEG, PNG, GIF, TXT, DOC, DOCX, JSON, XML'), false);
    }
  }
});

// Auth middleware for records
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    // Enforce subscriber-only access — responders and providers must use their own endpoints
    if (decoded.role !== 'subscriber') {
      return res.status(403).json({
        error: 'Access denied: medical records require subscriber authentication',
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

// Provider auth middleware for clinical notes
function providerAuthMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'provider') {
      return res.status(403).json({ error: 'Access denied: provider authentication required' });
    }
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// POST /api/records/upload - Upload medical record file
router.post('/upload', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    const db = req.app.locals.db;
    const { title, record_type, category, parent_record_id, overwrite, visibility: requestedVisibility } = req.body;
    const subscriberId = req.user.id;
    const subscriberDid = req.user.did;

    // Ensure file_hash column exists (lazy migration)
    await db.query(`
      ALTER TABLE medical_records ADD COLUMN IF NOT EXISTS file_hash VARCHAR(64)
    `).catch(() => {}); // ignore if already exists

    if (!title) {
      return res.status(400).json({ error: 'Record title is required' });
    }

    // ── Versioning: resolve parent/root record info ──────────────────────────
    let versionNumber = 1;
    let resolvedParentId = null;
    if (parent_record_id) {
      const refRecord = await db.query(
        'SELECT * FROM medical_records WHERE id = $1 AND subscriber_id = $2',
        [parseInt(parent_record_id), subscriberId]
      );
      if (refRecord.rows.length === 0) {
        return res.status(404).json({ error: 'Parent record not found or not authorized' });
      }
      // Resolve to root: if referenced record itself has a parent, use that as root
      const rootId = refRecord.rows[0].parent_record_id || parseInt(parent_record_id);
      resolvedParentId = rootId;
      // Find max version in this chain to compute next version
      const maxVerResult = await db.query(
        'SELECT COALESCE(MAX(version), 1) as max_version FROM medical_records WHERE id = $1 OR parent_record_id = $1',
        [rootId]
      );
      versionNumber = parseInt(maxVerResult.rows[0].max_version) + 1;
    }

    const filePath = req.file ? req.file.filename : null;
    const fileFormat = req.file ? req.file.mimetype : null;
    const fileSize = req.file ? req.file.size : 0;

    // ── Feature #386: Compute file hash for duplicate detection ──────────────
    let fileHash = null;
    if (req.file) {
      const fullFilePath = path.join(uploadsDir, req.file.filename);
      const fileBuffer = fs.readFileSync(fullFilePath);
      fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

      // Check for duplicate only when NOT a version upload and overwrite is not requested
      if (!parent_record_id && overwrite !== 'true') {
        const dupCheck = await db.query(
          'SELECT id, title, created_at FROM medical_records WHERE subscriber_id = $1 AND file_hash = $2 AND parent_record_id IS NULL LIMIT 1',
          [subscriberId, fileHash]
        );
        if (dupCheck.rows.length > 0) {
          // Clean up the uploaded file since we won't use it
          fs.unlink(fullFilePath, () => {});
          return res.status(409).json({
            error: 'Duplicate record detected',
            duplicate: true,
            existing_record: {
              id: dupCheck.rows[0].id,
              title: dupCheck.rows[0].title,
              created_at: dupCheck.rows[0].created_at,
            }
          });
        }
      }
    }

    // Attempt C-CDA/FHIR parsing for XML/JSON files (before encryption)
    let extractedData = null;
    if (req.file) {
      const ext = req.file.originalname.toLowerCase().split('.').pop();
      const isXml = ext === 'xml' || fileFormat === 'application/xml' || fileFormat === 'text/xml' || fileFormat === 'application/cda+xml';
      const isJson = ext === 'json' || fileFormat === 'application/json' || fileFormat === 'application/fhir+json';

      if (isXml) {
        try {
          const fullPath = path.join(uploadsDir, req.file.filename);
          const xmlContent = fs.readFileSync(fullPath, 'utf8');
          if (isCCDA(xmlContent)) {
            extractedData = parseCCDA(xmlContent);
            console.log(`[Records] C-CDA parsed for ${req.file.originalname}: ${JSON.stringify(extractedData.summary)}`);
          } else {
            // Generic XML - extract basic info
            extractedData = {
              format: 'XML',
              parsed_at: new Date().toISOString(),
              root_element: xmlContent.match(/<([a-zA-Z][^>\s/]*)/)?.[1] || 'unknown',
              is_ccda: false,
            };
          }
        } catch (parseErr) {
          console.error('[Records] XML parse error:', parseErr.message);
          extractedData = createRecordParseFailureMetadata({
            format: 'XML',
            stage: 'xml_parse',
          });
        }
      } else if (isJson) {
        try {
          const fullPath = path.join(uploadsDir, req.file.filename);
          const jsonContent = fs.readFileSync(fullPath, 'utf8');
          // Try parsing as JSON first to detect malformed files (#385)
          let parsedObj = null;
          try {
            parsedObj = JSON.parse(jsonContent);
          } catch (jsonErr) {
            // Truly malformed JSON - set parse_error and continue upload
            extractedData = createRecordParseFailureMetadata({
              format: 'JSON',
              stage: 'json_parse',
              code: 'invalid_json_format',
            });
            console.warn(`[Records] Malformed JSON for ${req.file.originalname}: ${jsonErr.message}`);
          }
          if (!extractedData) {
            if (isFHIR(parsedObj)) {
              extractedData = parseFHIR(parsedObj);
              console.log(`[Records] FHIR R4 parsed for ${req.file.originalname}: resourceType=${extractedData.resource_type}, summary=${JSON.stringify(extractedData.summary)}`);
            } else {
              extractedData = { format: 'JSON', parsed_at: new Date().toISOString(), is_fhir: false };
            }
          }
        } catch (parseErr) {
          console.error('[Records] JSON parse error:', parseErr.message);
          extractedData = createRecordParseFailureMetadata({
            format: 'JSON',
            stage: 'json_parse',
          });
        }
      }
    }

    // ── Feature #92: Encrypt uploaded file with subscriber's key ──────────────
    let encryptionInfo = null;
    let isEncrypted = false;
    if (req.file) {
      try {
        const encKey = await getOrCreateSubscriberEncryptionKey(db, subscriberId, subscriberDid);
        const fullFilePath = path.join(uploadsDir, req.file.filename);
        encryptionInfo = encryptFile(fullFilePath, encKey);
        isEncrypted = true;
        console.log(`[Records] File encrypted with AES-256-GCM for subscriber ${subscriberId}: ${req.file.filename}`);
      } catch (encErr) {
        console.error('[Records] Encryption error:', encErr.message);
        // Don't fail upload if encryption fails - still store but mark unencrypted
        isEncrypted = false;
      }
    }

    // Feature #283: Default visibility to 'private' (most restrictive) for new records
    const validVisibilities = ['all_providers', 'specific_providers', 'emergency_only', 'private'];
    const recordVisibility = (requestedVisibility && validVisibilities.includes(requestedVisibility))
      ? requestedVisibility
      : 'private';

    const result = await db.query(
      `INSERT INTO medical_records (subscriber_id, title, record_type, category, file_path, file_format, file_size, extracted_data, encrypted, version, parent_record_id, file_hash, visibility)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       RETURNING *`,
      [subscriberId, title, record_type || 'general', category || 'uncategorized', filePath, fileFormat, fileSize, extractedData ? JSON.stringify(extractedData) : null, isEncrypted, versionNumber, resolvedParentId, fileHash, recordVisibility]
    );

    console.log(`[Records] File uploaded: ${filePath} (${fileSize} bytes) for subscriber ${subscriberId}, encrypted=${isEncrypted}`);

    res.status(201).json({
      record: buildPublicMedicalRecordResponse(result.rows[0]),
      file: req.file ? {
        originalName: req.file.originalname,
        size: req.file.size,
        mimetype: req.file.mimetype
      } : null,
      extracted_data: extractedData,
      encryption: encryptionInfo,
      message: isEncrypted
        ? (extractedData && extractedData.format === 'C-CDA'
            ? 'C-CDA record uploaded, parsed, and encrypted successfully'
            : extractedData && extractedData.format === 'FHIR R4'
              ? 'FHIR R4 record uploaded, parsed, and encrypted successfully'
              : 'Record uploaded and encrypted successfully')
        : (extractedData && extractedData.format === 'C-CDA'
            ? 'C-CDA record uploaded and parsed successfully'
            : extractedData && extractedData.format === 'FHIR R4'
              ? 'FHIR R4 record uploaded and parsed successfully'
              : 'Record uploaded successfully')
    });
  } catch (err) {
    console.error('[Records] Upload error:', err.message);
    res.status(500).json({ error: 'Failed to upload record' });
  }
});

// GET /api/records - Get all records for authenticated subscriber
router.get('/', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const subscriberId = req.user.id;

    // Support pagination via ?page=N&limit=N query params
    const usePagination = req.query.page !== undefined || req.query.limit !== undefined;

    if (usePagination) {
      const page = Math.max(1, parseInt(req.query.page) || 1);
      const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 10));
      const offset = (page - 1) * limit;

      // Get total count
      const countResult = await db.query(
        'SELECT COUNT(*) FROM medical_records WHERE subscriber_id = $1',
        [subscriberId]
      );
      const total = parseInt(countResult.rows[0].count, 10);
      const pages = Math.ceil(total / limit);

      // Get paginated records
      const result = await db.query(
        `SELECT id, subscriber_id, title, record_type, category, file_path, file_format, file_size,
                extracted_data, annotation, encrypted, visibility, visibility_providers,
                version, parent_record_id,
                created_at, updated_at
         FROM medical_records WHERE subscriber_id = $1 ORDER BY created_at DESC
         LIMIT $2 OFFSET $3`,
        [subscriberId, limit, offset]
      );

      return res.json({
        data: buildPublicMedicalRecordListResponse(result.rows),
        pagination: {
          page,
          limit,
          total,
          pages,
        },
      });
    }

    // Default: return all records as flat array (backward compatible)
    const result = await db.query(
      `SELECT id, subscriber_id, title, record_type, category, file_path, file_format, file_size,
              extracted_data, annotation, encrypted, visibility, visibility_providers,
              version, parent_record_id,
              created_at, updated_at
       FROM medical_records WHERE subscriber_id = $1 ORDER BY created_at DESC`,
      [subscriberId]
    );

    return res.json(buildPublicMedicalRecordListResponse(result.rows));
  } catch (err) {
    console.error('[Records] Get records error:', err.message);
    res.status(500).json({ error: 'Failed to get records' });
  }
});

// GET /api/records/providers - List verified providers for records request dropdown (MUST be before /:id)
router.get('/providers', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const result = await db.query(
      `SELECT id, provider_name, npi, facility, specialty, npi_verified
       FROM providers
       WHERE npi_verified = true
       ORDER BY provider_name ASC`
    );
    res.json(buildPublicRecordProviderListResponse(result.rows));
  } catch (err) {
    console.error('[Records] Get providers error:', err.message);
    res.status(500).json({ error: 'Failed to get providers' });
  }
});

// GET /api/records/requests - Get record requests for authenticated subscriber (MUST be before /:id)
router.get('/requests', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const subscriberId = req.user.id;

    const result = await db.query(
      'SELECT * FROM record_requests WHERE subscriber_id = $1 ORDER BY sent_at DESC',
      [subscriberId]
    );

    res.json(result.rows.map(buildPublicRecordRequestResponse));
  } catch (err) {
    console.error('[Records] Get requests error:', err.message);
    res.status(500).json({ error: 'Failed to get record requests' });
  }
});

// GET /api/records/:id - Get a single record by ID
router.get('/:id', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const { id } = req.params;
    const subscriberId = req.user.id;

    const result = await db.query(
      `SELECT id, subscriber_id, title, record_type, category, file_path, file_format, file_size,
              extracted_data, annotation, encrypted, visibility, visibility_providers,
              version, parent_record_id, created_at, updated_at
       FROM medical_records WHERE id = $1 AND subscriber_id = $2`,
      [parseInt(id), subscriberId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Record not found' });
    }

    res.json(buildPublicMedicalRecordResponse(result.rows[0]));
  } catch (err) {
    console.error('[Records] Get record error:', err.message);
    res.status(500).json({ error: 'Failed to get record' });
  }
});

// GET /api/records/:id/versions - Get version history for a record
router.get('/:id/versions', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const { id } = req.params;
    const subscriberId = req.user.id;

    // Verify the record belongs to subscriber
    const refRecord = await db.query(
      'SELECT * FROM medical_records WHERE id = $1 AND subscriber_id = $2',
      [parseInt(id), subscriberId]
    );
    if (refRecord.rows.length === 0) {
      return res.status(404).json({ error: 'Record not found' });
    }

    // Find the root record id
    const rootId = refRecord.rows[0].parent_record_id || parseInt(id);

    // Get all versions in this chain
    const versions = await db.query(
      `SELECT id, title, record_type, category, file_path, file_format, file_size,
              version, parent_record_id, created_at, updated_at
       FROM medical_records
       WHERE (id = $1 OR parent_record_id = $1) AND subscriber_id = $2
       ORDER BY COALESCE(version, 1) ASC`,
      [rootId, subscriberId]
    );

    res.json(buildPublicMedicalRecordVersionEnvelope(versions.rows));
  } catch (err) {
    console.error('[Records] Get versions error:', err.message);
    res.status(500).json({ error: 'Failed to get record versions' });
  }
});

// GET /api/records/:id/download - Download/view a record (decrypts if encrypted) - Feature #92
router.get('/:id/download', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const { id } = req.params;
    const subscriberId = req.user.id;
    const subscriberDid = req.user.did;

    // Verify ownership - only subscriber can decrypt/view
    const result = await db.query(
      'SELECT * FROM medical_records WHERE id = $1 AND subscriber_id = $2',
      [id, subscriberId]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ error: 'Access denied. Record not found or not owned by subscriber.' });
    }

    const record = result.rows[0];
    if (!record.file_path) {
      return res.status(404).json({ error: 'No file attached to this record' });
    }

    const fullFilePath = path.join(uploadsDir, record.file_path);
    if (!fs.existsSync(fullFilePath)) {
      return res.status(404).json({ error: 'File not found on disk' });
    }

    const mimeType = record.file_format || 'application/octet-stream';
    res.setHeader('Content-Type', mimeType);
    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(record.title)}"`);
    res.setHeader('X-Record-Encrypted', record.encrypted ? 'true' : 'false');

    if (record.encrypted) {
      // Decrypt on-the-fly - only subscriber with their key can decrypt
      const encKey = await getOrCreateSubscriberEncryptionKey(db, subscriberId, subscriberDid);
      const decrypted = decryptFile(fullFilePath, encKey);
      res.setHeader('Content-Length', decrypted.length);
      res.setHeader('X-Record-Decrypted-For', subscriberDid || `sub-${subscriberId}`);
      res.send(decrypted);
    } else {
      fs.createReadStream(fullFilePath).pipe(res);
    }
  } catch (err) {
    console.error('[Records] Download error:', err.message);
    if (err.message && (err.message.includes('Unsupported state') || err.message.includes('auth'))) {
      return res.status(403).json({ error: 'Decryption failed. Access denied.' });
    }
    res.status(500).json({ error: 'Failed to download record' });
  }
});

// GET /api/records/:id/encryption-status - Check encryption status - Feature #92
router.get('/:id/encryption-status', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const { id } = req.params;
    const subscriberId = req.user.id;

    const result = await db.query(
      'SELECT id, title, encrypted, file_path FROM medical_records WHERE id = $1 AND subscriber_id = $2',
      [id, subscriberId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Record not found' });
    }

    const record = result.rows[0];
    res.json(buildPublicMedicalRecordEncryptionStatusResponse(record));
  } catch (err) {
    console.error('[Records] Encryption status error:', err.message);
    res.status(500).json({ error: 'Failed to get encryption status' });
  }
});

// PATCH /api/records/:id/visibility - Update visibility settings - Feature #95
// NOTE: Must be before /:id to avoid routing conflicts
router.patch('/:id/visibility', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const { id } = req.params;
    const subscriberId = req.user.id;
    const { visibility, visibility_providers } = req.body;

    const validVisibilities = ['all_providers', 'specific_providers', 'emergency_only', 'private'];
    if (!visibility || !validVisibilities.includes(visibility)) {
      return res.status(400).json({
        error: `Invalid visibility. Must be one of: ${validVisibilities.join(', ')}`
      });
    }

    // For specific_providers, providers list is required
    if (visibility === 'specific_providers' && (!visibility_providers || !Array.isArray(visibility_providers) || visibility_providers.length === 0)) {
      return res.status(400).json({ error: 'visibility_providers array required when visibility is specific_providers' });
    }

    // Verify ownership
    const existing = await db.query(
      'SELECT * FROM medical_records WHERE id = $1 AND subscriber_id = $2',
      [id, subscriberId]
    );

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Record not found' });
    }

    // Ensure visibility_providers column exists
    await db.query(`ALTER TABLE medical_records ADD COLUMN IF NOT EXISTS visibility_providers JSONB`).catch(() => {});

    const providersToStore = visibility === 'specific_providers' ? visibility_providers : null;

    const result = await db.query(
      `UPDATE medical_records SET visibility = $1, visibility_providers = $2, updated_at = NOW()
       WHERE id = $3 AND subscriber_id = $4 RETURNING *`,
      [visibility, providersToStore ? JSON.stringify(providersToStore) : null, parseInt(id), subscriberId]
    );

    console.log(`[Records] Record #${id} visibility set to '${visibility}' for subscriber ${subscriberId}`);
    res.json(buildPublicMedicalRecordResponse(result.rows[0]));
  } catch (err) {
    console.error('[Records] Update visibility error:', err.message);
    res.status(500).json({ error: 'Failed to update visibility' });
  }
});

// PATCH /api/records/:id - Update annotation and/or category - Feature #94
router.patch('/:id', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const { id } = req.params;
    const subscriberId = req.user.id;
    const { annotation, category, title } = req.body;

    // Verify ownership
    const existing = await db.query(
      'SELECT * FROM medical_records WHERE id = $1 AND subscriber_id = $2',
      [id, subscriberId]
    );

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Record not found' });
    }

    // Build dynamic update
    const updates = [];
    const params = [];
    let paramIdx = 1;

    if (annotation !== undefined) {
      updates.push(`annotation = $${paramIdx++}`);
      params.push(annotation || null);
    }
    if (category !== undefined) {
      updates.push(`category = $${paramIdx++}`);
      params.push(category || 'uncategorized');
    }
    if (title !== undefined) {
      updates.push(`title = $${paramIdx++}`);
      params.push(title || existing.rows[0].title);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update. Provide annotation, category, or title.' });
    }

    updates.push(`updated_at = NOW()`);
    params.push(parseInt(id), subscriberId);

    const result = await db.query(
      `UPDATE medical_records SET ${updates.join(', ')} WHERE id = $${paramIdx++} AND subscriber_id = $${paramIdx++} RETURNING *`,
      params
    );

    console.log(`[Records] Record #${id} updated: ${updates.join(', ')} for subscriber ${subscriberId}`);
    res.json(buildPublicMedicalRecordResponse(result.rows[0]));
  } catch (err) {
    console.error('[Records] Update record error:', err.message);
    res.status(500).json({ error: 'Failed to update record' });
  }
});

// DELETE /api/records/:id - Delete a record (audit trail preserved)
router.delete('/:id', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const { id } = req.params;
    const subscriberId = req.user.id;
    const subscriberDid = req.user.did;

    // Verify ownership
    const record = await db.query(
      'SELECT * FROM medical_records WHERE id = $1 AND subscriber_id = $2',
      [id, subscriberId]
    );

    if (record.rows.length === 0) {
      return res.status(404).json({ error: 'Record not found' });
    }

    const recordData = record.rows[0];

    // Create audit receipt BEFORE deletion (preserves record of what was deleted)
    const receiptHash = uuidv4();
    const deletionTimestamp = new Date().toISOString();
    await db.query(
      `INSERT INTO audit_receipts (subject_did, actor_did, event_type, scope, details, receipt_hash)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        subscriberDid || ('subscriber:' + subscriberId),
        subscriberDid || ('subscriber:' + subscriberId),
        'record_deleted',
        'health_vault',
        JSON.stringify(buildInactiveDeletionAuditMetadata({
          deletion_kind: 'medical_record_copy',
          record_id: parseInt(id),
          record_title: recordData.title,
          record_type: recordData.record_type,
          category: recordData.category,
          file_format: recordData.file_format,
          file_size: recordData.file_size,
          deleted_at: deletionTimestamp,
          subscriber_id: subscriberId,
        })),
        receiptHash
      ]
    );

    // Delete file if it exists
    if (recordData.file_path) {
      const fullPath = path.join(uploadsDir, recordData.file_path);
      if (fs.existsSync(fullPath)) {
        fs.unlinkSync(fullPath);
      }
    }

    await db.query('DELETE FROM medical_records WHERE id = $1', [id]);

    console.log(`[Records] Record #${id} deleted by subscriber ${subscriberId}; audit receipt ${receiptHash} preserved`);

    res.json(
      buildPublicMedicalRecordDeletionAcknowledgement({
        message: 'Record deleted successfully',
        audit_receipt: receiptHash,
      }),
    );
  } catch (err) {
    console.error('[Records] Delete error:', err.message);
    res.status(500).json({ error: 'Failed to delete record' });
  }
});

// POST /api/records/request - Create a HIPAA Right of Access records request
router.post('/request', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const subscriberId = req.user.id;
    const subscriberDid = req.user.did;
    const { provider_name, provider_npi, provider_address } = req.body;

    if (!provider_name || !provider_name.trim()) {
      return res.status(400).json({ error: 'Provider name is required' });
    }

    // Get subscriber details for the letter
    const subResult = await db.query(
      'SELECT first_name, last_name, email, did, date_of_birth FROM subscribers WHERE id = $1',
      [subscriberId]
    );
    const subscriberInfo = subResult.rows[0] || { email: 'N/A', did: subscriberDid };

    // Create the record request
    const result = await db.query(
      `INSERT INTO record_requests (subscriber_id, provider_name, provider_npi, provider_address, status)
       VALUES ($1, $2, $3, $4, 'sent')
       RETURNING *`,
      [subscriberId, provider_name.trim(), provider_npi || null, provider_address || null]
    );

    const request = result.rows[0];

    // Generate HIPAA request letter PDF
    try {
      const letterResult = await generateHIPAALetter(
        subscriberInfo,
        { name: provider_name.trim(), npi: provider_npi, address: provider_address },
        request.id
      );

      // Update the record request with the letter path
      await db.query(
        'UPDATE record_requests SET letter_pdf_path = $1 WHERE id = $2',
        [letterResult.filename, request.id]
      );
      request.letter_pdf_path = letterResult.filename;

      console.log(`[Records] HIPAA letter generated: ${letterResult.filename} for request #${request.id}`);
    } catch (pdfErr) {
      console.error('[Records] PDF generation error:', pdfErr.message);
      // Don't fail the request if PDF generation fails
    }

    console.log(`[Records] HIPAA Right of Access request created: subscriber=${subscriberId}, provider=${provider_name}, status=sent`);

    res.status(201).json(buildPublicRecordRequestResponse(request));
  } catch (err) {
    console.error('[Records] Request error:', err.message);
    res.status(500).json({ error: 'Failed to create records request' });
  }
});

// GET /api/records/request/:id/letter - Download HIPAA request letter PDF
router.get('/request/:id/letter', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const { id } = req.params;
    const subscriberId = req.user.id;

    // Verify ownership
    const result = await db.query(
      'SELECT * FROM record_requests WHERE id = $1 AND subscriber_id = $2',
      [id, subscriberId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Request not found' });
    }

    const request = result.rows[0];
    if (!request.letter_pdf_path) {
      return res.status(404).json({ error: 'Letter not yet generated' });
    }

    const filePath = path.join(lettersDir, request.letter_pdf_path);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Letter file not found' });
    }

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="HIPAA_Request_${request.provider_name.replace(/[^a-zA-Z0-9]/g, '_')}_${id}.pdf"`);
    fs.createReadStream(filePath).pipe(res);
  } catch (err) {
    console.error('[Records] Letter download error:', err.message);
    res.status(500).json({ error: 'Failed to download letter' });
  }
});

// GET /api/records/requests/:subscriberDid - Get record requests by DID (legacy)
router.get('/requests/:subscriberDid', async (req, res) => {
  try {
    const db = req.app.locals.db;
    const { subscriberDid } = req.params;

    const subResult = await db.query('SELECT id FROM subscribers WHERE did = $1', [subscriberDid]);
    if (subResult.rows.length === 0) {
      return res.status(404).json({ error: 'Subscriber not found' });
    }

    const result = await db.query(
      'SELECT * FROM record_requests WHERE subscriber_id = $1 ORDER BY sent_at DESC',
      [subResult.rows[0].id]
    );

    res.json(result.rows.map(buildPublicRecordRequestResponse));
  } catch (err) {
    console.error('[Records] Get requests error:', err.message);
    res.status(500).json({ error: 'Failed to get record requests' });
  }
});

// PATCH /api/records/requests/:id/status - Update status of a records request (Feature #89)
// Valid statuses: sent, pending, received, failed
router.patch('/requests/:id/status', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const { id } = req.params;
    const subscriberId = req.user.id;
    const { status, notes } = req.body;

    const validStatuses = ['sent', 'pending', 'received', 'failed'];
    if (!status || !validStatuses.includes(status)) {
      return res.status(400).json({
        error: `Invalid status. Must be one of: ${validStatuses.join(', ')}`
      });
    }

    // Verify the request belongs to this subscriber
    const existingResult = await db.query(
      'SELECT * FROM record_requests WHERE id = $1 AND subscriber_id = $2',
      [parseInt(id), subscriberId]
    );
    if (existingResult.rows.length === 0) {
      return res.status(404).json({ error: 'Request not found' });
    }

    // Ensure timestamp columns and status_notes exist
    try {
      await db.query(`ALTER TABLE record_requests ADD COLUMN IF NOT EXISTS status_notes TEXT`);
      await db.query(`ALTER TABLE record_requests ADD COLUMN IF NOT EXISTS pending_at TIMESTAMPTZ`);
    } catch (_) {}

    let updateQuery;
    let params;

    if (status === 'received') {
      updateQuery = 'UPDATE record_requests SET status = $1, received_at = NOW(), status_notes = $2 WHERE id = $3 AND subscriber_id = $4 RETURNING *';
      params = [status, notes || null, parseInt(id), subscriberId];
    } else if (status === 'pending') {
      updateQuery = 'UPDATE record_requests SET status = $1, pending_at = NOW(), status_notes = $2 WHERE id = $3 AND subscriber_id = $4 RETURNING *';
      params = [status, notes || null, parseInt(id), subscriberId];
    } else {
      updateQuery = 'UPDATE record_requests SET status = $1, status_notes = $2 WHERE id = $3 AND subscriber_id = $4 RETURNING *';
      params = [status, notes || null, parseInt(id), subscriberId];
    }

    const result = await db.query(updateQuery, params);
    const updated = result.rows[0];

    console.log(`[Records] Request #${id} status updated to '${status}' by subscriber #${subscriberId}`);
    res.json(buildPublicRecordRequestResponse(updated));
  } catch (err) {
    console.error('[Records] Update request status error:', err.message);
    res.status(500).json({ error: 'Failed to update request status' });
  }
});

// ─── PROVIDER CLINICAL NOTES (Feature #107) ─────────────────────────────────
// POST /api/records/clinical-notes - Provider adds a clinical note to subscriber record
router.post('/clinical-notes', providerAuthMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const providerId = req.user.id;
    const { subscriber_id, note_text, note_type } = req.body;

    if (!subscriber_id) {
      return res.status(400).json({ error: 'subscriber_id is required' });
    }
    if (!note_text || !note_text.trim()) {
      return res.status(400).json({ error: 'note_text is required' });
    }

    // Verify provider has active consent for this subscriber
    const consentCheck = await db.query(
      `SELECT id FROM consent_events WHERE provider_id = $1 AND subscriber_id = $2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW()) LIMIT 1`,
      [providerId, subscriber_id]
    );
    if (consentCheck.rows.length === 0) {
      return res.status(403).json({ error: 'No active consent from this subscriber. Cannot add clinical notes.' });
    }

    // Ensure provider_clinical_notes table exists
    await db.query(`
      CREATE TABLE IF NOT EXISTS provider_clinical_notes (
        id SERIAL PRIMARY KEY,
        subscriber_id INTEGER NOT NULL REFERENCES subscribers(id),
        provider_id INTEGER NOT NULL REFERENCES providers(id),
        note_text TEXT NOT NULL,
        note_type VARCHAR(100) DEFAULT 'clinical_note',
        status VARCHAR(50) DEFAULT 'pending_approval',
        approved_at TIMESTAMP WITH TIME ZONE,
        rejected_at TIMESTAMP WITH TIME ZONE,
        reject_reason TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    const result = await db.query(
      `INSERT INTO provider_clinical_notes (subscriber_id, provider_id, note_text, note_type, status)
       VALUES ($1, $2, $3, $4, 'pending_approval')
       RETURNING *`,
      [subscriber_id, providerId, note_text.trim(), note_type || 'clinical_note']
    );

    const note = result.rows[0];

    // Notify subscriber of pending note
    await db.query(
      `INSERT INTO notifications (subscriber_id, type, title, body) VALUES ($1, $2, $3, $4)`,
      [subscriber_id, 'provider_note_pending', 'Provider Clinical Note Pending Approval',
        JSON.stringify({ note_id: note.id, provider_id: providerId, note_type: note.note_type, created_at: note.created_at })]
    ).catch(() => {});

    console.log(`[Records] Provider ${providerId} added clinical note for subscriber ${subscriber_id}, note #${note.id} (pending approval)`);
    res.status(201).json(
      buildPublicClinicalNoteCreateAcknowledgement({
        note,
        message: 'Clinical note submitted and awaiting subscriber approval.',
      }),
    );
  } catch (err) {
    console.error('[Records] Clinical note create error:', err.message);
    res.status(500).json({ error: 'Failed to create clinical note' });
  }
});

// GET /api/records/clinical-notes/subscriber - Subscriber views notes requiring approval
router.get('/clinical-notes/subscriber', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const subscriberId = req.user.id;

    // Ensure table exists
    await db.query(`
      CREATE TABLE IF NOT EXISTS provider_clinical_notes (
        id SERIAL PRIMARY KEY,
        subscriber_id INTEGER NOT NULL,
        provider_id INTEGER NOT NULL,
        note_text TEXT NOT NULL,
        note_type VARCHAR(100) DEFAULT 'clinical_note',
        status VARCHAR(50) DEFAULT 'pending_approval',
        approved_at TIMESTAMP WITH TIME ZONE,
        rejected_at TIMESTAMP WITH TIME ZONE,
        reject_reason TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    const result = await db.query(
      `SELECT pcn.*, COALESCE(p.provider_name, p.email) AS provider_display_name, COALESCE(p.provider_name, p.email) AS provider_first_name, '' AS provider_last_name, p.email AS provider_email, p.did AS provider_did
       FROM provider_clinical_notes pcn
       JOIN providers p ON p.id = pcn.provider_id
       WHERE pcn.subscriber_id = $1
       ORDER BY pcn.created_at DESC`,
      [subscriberId]
    );

    const notes = result.rows;

    res.json(buildPublicClinicalNoteListEnvelope(notes));
  } catch (err) {
    console.error('[Records] Subscriber get clinical notes error:', err.message);
    res.status(500).json({ error: 'Failed to load clinical notes' });
  }
});

// GET /api/records/clinical-notes/provider - Provider views notes they submitted
router.get('/clinical-notes/provider', providerAuthMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const providerId = req.user.id;

    await db.query(`
      CREATE TABLE IF NOT EXISTS provider_clinical_notes (
        id SERIAL PRIMARY KEY,
        subscriber_id INTEGER NOT NULL,
        provider_id INTEGER NOT NULL,
        note_text TEXT NOT NULL,
        note_type VARCHAR(100) DEFAULT 'clinical_note',
        status VARCHAR(50) DEFAULT 'pending_approval',
        approved_at TIMESTAMP WITH TIME ZONE,
        rejected_at TIMESTAMP WITH TIME ZONE,
        reject_reason TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    const result = await db.query(
      `SELECT pcn.*, s.first_name AS subscriber_first_name, s.last_name AS subscriber_last_name, s.did AS subscriber_did
       FROM provider_clinical_notes pcn
       JOIN subscribers s ON s.id = pcn.subscriber_id
       WHERE pcn.provider_id = $1
       ORDER BY pcn.created_at DESC`,
      [providerId]
    );

    res.json(buildPublicClinicalNoteListEnvelope(result.rows));
  } catch (err) {
    console.error('[Records] Provider get clinical notes error:', err.message);
    res.status(500).json({ error: 'Failed to load clinical notes' });
  }
});

// PATCH /api/records/clinical-notes/:id/approve - Subscriber approves a provider note
router.patch('/clinical-notes/:id/approve', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const subscriberId = req.user.id;
    const noteId = parseInt(req.params.id);

    const result = await db.query(
      `UPDATE provider_clinical_notes
       SET status = 'approved', approved_at = NOW(), updated_at = NOW()
       WHERE id = $1 AND subscriber_id = $2 AND status = 'pending_approval'
       RETURNING *`,
      [noteId, subscriberId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Note not found or not pending approval' });
    }

    const note = result.rows[0];

    // Create audit receipt for note approval
    const receiptHash = crypto.randomBytes(32).toString('hex');
    await db.query(
      `INSERT INTO audit_receipts (subject_did, actor_did, event_type, scope, details, receipt_hash)
       SELECT s.did, s.did, 'provider_note_approved', 'clinical_note', $1::jsonb, $2
       FROM subscribers s WHERE s.id = $3`,
      [JSON.stringify({ note_id: note.id, provider_id: note.provider_id, approved_at: note.approved_at }), receiptHash, subscriberId]
    ).catch(() => {});

    res.json(
      buildPublicClinicalNoteMutationAcknowledgement({
        note,
        message: 'Clinical note approved and added to your record.',
      }),
    );
  } catch (err) {
    console.error('[Records] Approve clinical note error:', err.message);
    res.status(500).json({ error: 'Failed to approve clinical note' });
  }
});

// PATCH /api/records/clinical-notes/:id/reject - Subscriber rejects a provider note
router.patch('/clinical-notes/:id/reject', authMiddleware, async (req, res) => {
  try {
    const db = req.app.locals.db;
    const subscriberId = req.user.id;
    const noteId = parseInt(req.params.id);
    const { reason } = req.body;

    const result = await db.query(
      `UPDATE provider_clinical_notes
       SET status = 'rejected', rejected_at = NOW(), reject_reason = $3, updated_at = NOW()
       WHERE id = $1 AND subscriber_id = $2 AND status = 'pending_approval'
       RETURNING *`,
      [noteId, subscriberId, reason || null]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Note not found or not pending approval' });
    }

    res.json(
      buildPublicClinicalNoteMutationAcknowledgement({
        note: result.rows[0],
        message: 'Clinical note rejected.',
      }),
    );
  } catch (err) {
    console.error('[Records] Reject clinical note error:', err.message);
    res.status(500).json({ error: 'Failed to reject clinical note' });
  }
});

// Handle multer errors
router.use((err, req, res, next) => {
  if (err) {
    return sendError(res, err, 'Medical record upload request could not be processed.', {
      correlationId: req.correlationId,
    });
  }
  next();
});

module.exports = router;
