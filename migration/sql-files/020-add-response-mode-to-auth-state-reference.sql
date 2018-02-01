-- Alter Oauth state reference table to add response_mode used in oauth workflow
ALTER TABLE oauth_state_references ADD COLUMN response_mode TEXT;
