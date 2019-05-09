-- drop some constraints and recreate them, but only as DEFERRABLE
ALTER table resource_type drop constraint resource_type_default_role_id_fkey;
ALTER table resource_type add constraint resource_type_default_role_id_fkey FOREIGN KEY (default_role_id) REFERENCES role(role_id) DEFERRABLE INITIALLY IMMEDIATE;
