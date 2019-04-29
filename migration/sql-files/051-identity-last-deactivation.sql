-- Add a column to track when the last deactivation attempt was made for an identity
ALTER TABLE identities ADD COLUMN deactivation_attempt timestamp with time zone;
