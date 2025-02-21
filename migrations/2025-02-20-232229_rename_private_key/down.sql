-- This file should undo anything in `up.sql`
ALTER TABLE jwks RENAME COLUMN private_key TO d;