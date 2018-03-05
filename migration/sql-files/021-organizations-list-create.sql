ALTER TABLE identity_role drop column identity_role_id;
ALTER TABLE identity_role ADD COLUMN identity_role_id uuid DEFAULT uuid_generate_v4();
ALTER TABLE identity_role ADD CONSTRAINT pk_identity_role PRIMARY KEY (identity_role_id);
CREATE UNIQUE INDEX uq_identity_role_identity_role_resource ON identity_role (identity_id, resource_id, role_id);

CREATE UNIQUE INDEX uq_role_resource_type_name ON role (resource_type_id, name);

INSERT INTO resource_type (name) VALUES ('identity/organization');

INSERT INTO role (role_id, resource_type_id, name) select uuid_generate_v4(), resource_type_id, 'owner' from resource_type where name = 'identity/organization';