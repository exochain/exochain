-- VitalLock: E2E encrypted messaging + digital legacy platform
-- Built on EXOCHAIN constitutional trust fabric

-- VitalLock user profiles (extends users table via FK)
CREATE TABLE IF NOT EXISTS vitallock_profiles (
    did TEXT PRIMARY KEY REFERENCES users(did),
    display_name TEXT,
    personality_data JSONB DEFAULT '{}',
    avatar_status TEXT DEFAULT 'pending',
    onboarding_complete BOOLEAN DEFAULT FALSE,
    subscription_tier TEXT DEFAULT 'free',
    x25519_public_key_hex TEXT,
    odentity_score INTEGER DEFAULT 0,
    created_at_ms BIGINT NOT NULL
);

-- PACE trustee network (1:4 viral growth)
CREATE TABLE IF NOT EXISTS pace_network (
    id BIGSERIAL PRIMARY KEY,
    owner_did TEXT NOT NULL REFERENCES users(did),
    trustee_did TEXT,
    trustee_email TEXT NOT NULL,
    trustee_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('Primary','Alternate','Contingency','Emergency')),
    relationship TEXT,
    invitation_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (invitation_status IN ('pending','accepted','declined','expired')),
    shamir_share_encrypted TEXT,
    invitation_token TEXT UNIQUE,
    created_at_ms BIGINT NOT NULL,
    accepted_at_ms BIGINT,
    UNIQUE(owner_did, trustee_email)
);
CREATE INDEX IF NOT EXISTS idx_pace_owner ON pace_network(owner_did);
CREATE INDEX IF NOT EXISTS idx_pace_trustee ON pace_network(trustee_did);
CREATE INDEX IF NOT EXISTS idx_pace_token ON pace_network(invitation_token);

-- Encrypted messages
CREATE TABLE IF NOT EXISTS encrypted_messages (
    id TEXT PRIMARY KEY,
    sender_did TEXT NOT NULL,
    recipient_did TEXT NOT NULL,
    envelope JSONB NOT NULL,
    content_type TEXT NOT NULL,
    subject TEXT,
    release_on_death BOOLEAN DEFAULT FALSE,
    release_delay_hours INTEGER DEFAULT 0,
    released BOOLEAN DEFAULT FALSE,
    read_at_ms BIGINT,
    deleted_by_sender BOOLEAN DEFAULT FALSE,
    deleted_by_recipient BOOLEAN DEFAULT FALSE,
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON encrypted_messages(recipient_did);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON encrypted_messages(sender_did);
CREATE INDEX IF NOT EXISTS idx_messages_death ON encrypted_messages(release_on_death)
    WHERE release_on_death = TRUE AND released = FALSE;

-- Digital assets vault
CREATE TABLE IF NOT EXISTS digital_assets (
    id TEXT PRIMARY KEY,
    owner_did TEXT NOT NULL REFERENCES users(did),
    asset_type TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    encrypted_payload BYTEA,
    encrypted_metadata JSONB DEFAULT '{}',
    file_size INTEGER,
    beneficiary_did TEXT,
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assets_owner ON digital_assets(owner_did);

-- Death verification requests
CREATE TABLE IF NOT EXISTS death_verification (
    id TEXT PRIMARY KEY,
    subject_did TEXT NOT NULL,
    initiated_by TEXT NOT NULL,
    required_confirmations INTEGER NOT NULL DEFAULT 3,
    trustee_confirmations JSONB DEFAULT '[]',
    verification_state JSONB NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','verified','rejected')),
    created_at_ms BIGINT NOT NULL,
    resolved_at_ms BIGINT
);
CREATE INDEX IF NOT EXISTS idx_death_subject ON death_verification(subject_did);

-- Family members / access control
CREATE TABLE IF NOT EXISTS family_members (
    id BIGSERIAL PRIMARY KEY,
    owner_did TEXT NOT NULL REFERENCES users(did),
    member_name TEXT NOT NULL,
    member_email TEXT NOT NULL,
    member_did TEXT,
    relationship TEXT NOT NULL,
    access_level TEXT DEFAULT 'view'
        CHECK (access_level IN ('view','limited','full')),
    permissions JSONB DEFAULT '{}',
    status TEXT DEFAULT 'pending'
        CHECK (status IN ('pending','active','revoked')),
    invited_at_ms BIGINT NOT NULL,
    joined_at_ms BIGINT
);
CREATE INDEX IF NOT EXISTS idx_family_owner ON family_members(owner_did);

-- Message templates
CREATE TABLE IF NOT EXISTS message_templates (
    id TEXT PRIMARY KEY,
    owner_did TEXT NOT NULL REFERENCES users(did),
    name TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'Text',
    subject_template TEXT,
    body_template TEXT NOT NULL,
    is_system BOOLEAN DEFAULT FALSE,
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_templates_owner ON message_templates(owner_did);

-- Insert default system templates
INSERT INTO message_templates (id, owner_did, name, content_type, subject_template, body_template, is_system, created_at_ms)
VALUES
    ('tpl-bank-login', 'system', 'Bank Login Credentials', 'Password', 'Bank Account Access', 'Bank: {{bank_name}}\nUsername: {{username}}\nPassword: {{password}}\nSecurity Questions: {{security_questions}}', TRUE, 0),
    ('tpl-last-words', 'system', 'Last Words', 'AfterlifeMessage', 'A Message From Beyond', 'Dear {{recipient_name}},\n\nIf you are reading this, I have passed on.\n\n{{message}}\n\nWith love,\n{{sender_name}}', TRUE, 0),
    ('tpl-safe-combo', 'system', 'Safe Combination', 'Secret', 'Safe Access', 'Location: {{location}}\nCombination: {{combination}}\nNotes: {{notes}}', TRUE, 0),
    ('tpl-will-instructions', 'system', 'Will Instructions', 'AfterlifeMessage', 'Important Instructions', 'Dear {{executor_name}},\n\nPlease follow these instructions regarding my estate:\n\n{{instructions}}\n\nAttorney: {{attorney_name}} ({{attorney_phone}})', TRUE, 0)
ON CONFLICT (id) DO NOTHING;
