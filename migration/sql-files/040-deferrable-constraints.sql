-- drop some constraints and recreate them, but only as DEFERRABLE
ALTER table default_role_mapping drop constraint default_role_mapping_from_role_id_fkey;
ALTER table default_role_mapping add constraint default_role_mapping_from_role_id_fkey FOREIGN KEY (from_role_id) REFERENCES role(role_id) DEFERRABLE INITIALLY IMMEDIATE;

ALTER table default_role_mapping drop constraint default_role_mapping_resource_type_id_fkey;
ALTER table default_role_mapping add constraint default_role_mapping_resource_type_id_fkey FOREIGN KEY (resource_type_id) REFERENCES resource_type(resource_type_id) DEFERRABLE INITIALLY IMMEDIATE;

ALTER table default_role_mapping drop constraint default_role_mapping_to_role_id_fkey;
ALTER table default_role_mapping add constraint default_role_mapping_to_role_id_fkey FOREIGN KEY (to_role_id) REFERENCES role(role_id) DEFERRABLE INITIALLY IMMEDIATE;