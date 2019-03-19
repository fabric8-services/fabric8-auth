-- Add a column to track when the user was notified about the forthcoming account deactivation
ALTER TABLE identities ADD COLUMN deactivation_notification timestamp with time zone;
-- index identities on the 2 columns used to list users to notify before deactivation
CREATE INDEX identities_deactivation_idx on identities using btree (last_active, deactivation_notification);
