ALTER TABLE jwks ADD COLUMN private_key_expires_at TIMESTAMP;
ALTER TABLE jwks ADD COLUMN key_expires_at TIMESTAMP;