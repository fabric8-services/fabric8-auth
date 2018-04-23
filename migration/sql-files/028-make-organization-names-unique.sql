UPDATE resource_type SET name = 'organization_remove' WHERE name = 'identity/organization';
INSERT INTO resource_type (resource_type_id, name) VALUES ('66659ea9-aa0a-4737-96e2-e96e615dc280', 'identity/organization');

UPDATE resource SET resource_type_id = '66659ea9-aa0a-4737-96e2-e96e615dc280' WHERE resource_type_id = (SELECT resource_type_id FROM resource_type WHERE name = 'organization_remove');
UPDATE resource_type_scope SET resource_type_id = '66659ea9-aa0a-4737-96e2-e96e615dc280' WHERE resource_type_id = (SELECT resource_type_id FROM resource_type WHERE name = 'organization_remove');

UPDATE resource ur set name = rs.updated_name
FROM (SELECT resource_id, name || ' (' || ROW_NUMBER() OVER (PARTITION BY (name) ORDER BY (created_at)) || ')' updated_name FROM resource WHERE resource_id NOT IN (
  SELECT resource_id FROM (SELECT resource_id, ROW_NUMBER() OVER (PARTITION BY name ORDER BY created_at) nth FROM resource WHERE resource_type_id = '66659ea9-aa0a-4737-96e2-e96e615dc280') numbered WHERE nth = 1)) rs
WHERE ur.resource_id = rs.resource_id AND ur.resource_type_id = '66659ea9-aa0a-4737-96e2-e96e615dc280';

CREATE UNIQUE INDEX unique_organization_names
ON resource (name)
WHERE resource_type_id = '66659ea9-aa0a-4737-96e2-e96e615dc280';

DELETE resource_type WHERE name = 'organization_remove'; 
