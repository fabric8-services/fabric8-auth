-- Add a column to track when deactivation has been scheduled for an identity
ALTER TABLE identities ADD COLUMN deactivation_scheduled timestamp with time zone;
