-- Delete resource type scopes
DELETE FROM resource_type_scope;

-- Delete resource types
DELETE FROM resource_type;

-- Delete resources
DELETE FROM resource;

-- Delete unnecessary description columns
ALTER TABLE resource_type DROP COLUMN description;
ALTER TABLE resource_type_scope DROP COLUMN description;
ALTER TABLE resource DROP COLUMN description;

-- Add unique constraint to resource_type.name.  Adding a unique constraint 
-- automatically creates an index to enforce that constraint.
ALTER TABLE resource_type ADD UNIQUE (name);

-- Create default resource type
INSERT INTO resource_type (
    name,
    created_at)
VALUES (
    'openshift.io/resource/area',
    now()
);
