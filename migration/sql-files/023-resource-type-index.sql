-- avoid the sequence scan 
CREATE INDEX IF NOT EXISTS idx_name_rt_name ON resource_type(name);

--- The ROLE_SCOPE table had a composite primary key (PK) of ( role_id,scope_id ) 
--- As part of the following change, a new ID column is added which is made the PK.
--- The old PK ie ( role_id,scope_id ) is being made a Unique Key.
--- Why ?
----
--- 1. To keep things consistent with all other tables.
--- 2. The gormsupport/cleaner/db_clean.go depends on using the entity's KEY attribute to 
--- clean up the rows after tests. When there's no single attribute that's a primary key, the implicit cleanup logic
--- breaks. That ends up with tests producing a lot of data which don't get cleaned up in the end. This causes a cascade of failed
--- cleanups, upto the RESOURCE_TYPE table.
---
--- Adding a new ID column helped avoid doing unnecesary refactoring of the cleanup code ( which worked for all other tables )
--- without having to change the way we queried the ROLE_SCOPE table in the business/model/service code.

ALTER TABLE ROLE_SCOPE DROP CONSTRAINT ROLE_SCOPE_PKEY;
ALTER TABLE ROLE_SCOPE ADD ID UUID PRIMARY KEY DEFAULT uuid_generate_v4();
CREATE UNIQUE INDEX ux_role_scope_id  ON role_scope (scope_id,role_id);