ALTER TABLE identity_role drop column identity_role_id;
ALTER TABLE identity_role ADD COLUMN identity_role_id uuid DEFAULT uuid_generate_v4();