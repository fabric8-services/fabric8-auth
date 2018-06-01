/* Change the organization 'owner' role to 'admin' */
UPDATE role SET name = 'admin' WHERE name = 'owner' AND resource_type_id = (SELECT resource_type_id FROM resource_type WHERE name = 'identity/organization');

/* Change the organization 'manage_members' scope to just 'manage' */
UPDATE resource_type_scope SET name = 'manage' WHERE name = 'manage_members' AND resource_type_id = (SELECT resource_type_id FROM resource_type WHERE name = 'identity/organization');

/* Delete the team 'admin' role */
DELETE FROM role_scope WHERE role_id = '4e03c5df-d3f6-4665-9ffa-4bef05355744';
DELETE FROM identity_role WHERE role_id = '4e03c5df-d3f6-4665-9ffa-4bef05355744';
DELETE FROM role WHERE role_id = '4e03c5df-d3f6-4665-9ffa-4bef05355744';

/* Delete the team 'manage' scope */
DELETE FROM resource_type_scope WHERE name = 'manage' AND resource_type_id = (SELECT resource_type_id FROM resource_type WHERE name = 'identity/team');