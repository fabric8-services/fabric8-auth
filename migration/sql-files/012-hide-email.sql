ALTER TABLE users ADD COLUMN email_private boolean;
UPDATE USERS SET email_private = false;
ALTER TABLE USERS ALTER COLUMN email_private set NOT NULL;