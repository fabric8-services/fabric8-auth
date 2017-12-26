-- Store identity provider username for the external token
ALTER TABLE users ADD COLUMN email_private boolean;
UPDATE USERS SET email_private = false;