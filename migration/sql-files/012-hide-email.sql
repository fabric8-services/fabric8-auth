-- Store identity provider username for the external token
ALTER TABLE users ADD COLUMN email_hidden boolean;
UPDATE USERS SET email_hidden = false;