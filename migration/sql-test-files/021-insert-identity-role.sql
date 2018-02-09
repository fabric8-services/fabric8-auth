INSERT INTO "resource_type" ("resource_type_id","name") VALUES('8e8bc9e2-6a24-47f8-a98f-6c1043143390','openshift.io/some/resourcetype');
INSERT INTO resource("resource_id","resource_type_id","name") VALUES ('4c169372-3b8a-4014-8017-49867b8681a7','8e8bc9e2-6a24-47f8-a98f-6c1043143390','SpaceR');
INSERT INTO role("role_id","resource_type_id","name") VALUES ('6008c541-15da-4662-9641-448ded5422da','8e8bc9e2-6a24-47f8-a98f-6c1043143390','collab');
INSERT INTO identities("id","username","registration_completed","provider_type") VALUES ('eca0ff77-4a85-408a-ad8e-729f8bdb96d9','f2ede785-9836-4235-93a1-8f037a284f12','false','kc');
INSERT INTO identity_role("identity_role_id","identity_id","resource_id","role_id") VALUES ('1a2a6b3a-f636-4246-a718-b662292897ba','eca0ff77-4a85-408a-ad8e-729f8bdb96d9','4c169372-3b8a-4014-8017-49867b8681a7','6008c541-15da-4662-9641-448ded5422da');
