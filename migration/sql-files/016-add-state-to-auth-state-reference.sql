-- Alter Oauth state reference table to add state used in oauth workflow
ALTER TABLE oauth_state_references ADD COLUMN state TEXT unique;
UPDATE oauth_state_references SET state = ID;
ALTER TABLE oauth_state_references ALTER state SET NOT NULL;
ALTER TABLE oauth_state_references ADD CONSTRAINT notemptystate check (state <> '');