-- This file should undo anything in `up.sql`
ALTER TABLE jwks DROP COLUMN x5t;
ALTER TABLE jwks DROP COLUMN x5c;