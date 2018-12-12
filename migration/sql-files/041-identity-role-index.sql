DROP INDEX uq_identity_role_identity_role_resource;
CREATE UNIQUE INDEX uq_identity_role_identity_role_resource ON identity_role (identity_id, resource_id, role_id) where deleted_at is null;
