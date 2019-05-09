-- drop some constraints and recreate them, but only as DEFERRABLE
ALTER table resource_type drop constraint resource_type_default_role_id_fkey;
ALTER table resource_type add constraint resource_type_default_role_id_fkey FOREIGN KEY (default_role_id) REFERENCES role(role_id) DEFERRABLE INITIALLY IMMEDIATE;

ALTER table resource drop constraint resource_parent_resource_id_fkey;
ALTER table resource add constraint resource_parent_resource_id_fkey FOREIGN KEY (parent_resource_id) REFERENCES resource(resource_id) DEFERRABLE INITIALLY IMMEDIATE;

ALTER table identity_role drop constraint identity_role_resource_id_fkey;
ALTER table identity_role add constraint identity_role_resource_id_fkey FOREIGN KEY (resource_id) REFERENCES resource(resource_id) DEFERRABLE INITIALLY IMMEDIATE;
