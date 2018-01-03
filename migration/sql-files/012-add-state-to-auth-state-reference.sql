-- Alter Oauth state reference table to add state used in oauth workflow
ALTER TABLE oauth_state_references ADD COLUMN state TEXT;