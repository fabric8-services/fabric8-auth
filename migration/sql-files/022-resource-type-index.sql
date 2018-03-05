CREATE INDEX IF NOT EXISTS idx_name_rt_name ON resource_type(name);
ALTER TABLE ROLE_SCOPE DROP CONSTRAINT ROLE_SCOPE_PKEY;
ALTER TABLE ROLE_SCOPE ADD ID UUID PRIMARY KEY DEFAULT uuid_generate_v4();
CREATE UNIQUE INDEX ux_role_scope_id  ON role_scope (scope_id,role_id);