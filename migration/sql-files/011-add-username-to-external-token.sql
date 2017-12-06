-- Store identity provider username for the external token
ALTER TABLE external_tokens ADD COLUMN username TEXT;
