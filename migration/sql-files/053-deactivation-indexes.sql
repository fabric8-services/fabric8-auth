-- change the indexes to match the WHERE clauses in the SELECT queries to notify and deactivate users
DROP INDEX identities_deactivation_idx;
CREATE INDEX identities_deactivation_nootification_idx ON identities USING btree (last_active, deactivation_notification, provider_type);
CREATE INDEX identities_deactivation_idx ON identities USING btree (last_active, deactivation_notification, deactivation_scheduled, provider_type);

