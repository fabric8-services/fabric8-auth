 /* Create a test organization */
 INSERT INTO resource (resource_id, name, resource_type_id) SELECT '682752ae-e03b-4d74-8b9a-e1d09f618ca5', 'Test Organization', resource_type_id FROM resource_type WHERE name = 'identity/organization';
 INSERT INTO identities (id, identity_resource_id) VALUES ('c62d77b2-194c-47d0-8bbf-b1308576876d', '682752ae-e03b-4d74-8b9a-e1d09f618ca5');
 
 /* Create a test resource */
 INSERT INTO resource (resource_id, name, resource_type_id) SELECT 'c6a2ee2e-7ec6-4c04-ae7e-5ff8c36b28b9', 'Test Area', resource_type_id FROM resource_type WHERE name = 'openshift.io/resource/area';
 
 /* Create a test user identity */
 INSERT INTO identities (id) VALUES ('d9161547-5263-4c83-a729-e39ff088978e');
