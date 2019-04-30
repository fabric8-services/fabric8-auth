-- Add a column to track when deactivation has been scheduled for an identity
ALTER TABLE identities ADD COLUMN deactivation_scheduled timestamp with time zone;
CREATE INDEX idx_identities_deactivation_scheduled on identities using btree (deactivation_scheduled);