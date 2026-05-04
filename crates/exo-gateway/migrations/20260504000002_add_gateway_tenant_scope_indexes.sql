CREATE INDEX IF NOT EXISTS idx_users_tenant_created_at ON users(tenant_id, created_at);
