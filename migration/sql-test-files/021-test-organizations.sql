insert into resource_type (resource_type_id, name) values ('c3605c89-d2ae-4d3f-b4b6-dc0078531c9e', 'resource/migration-test');
insert into resource (resource_id, resource_type_id, name) values('9c17b0a3-a56e-4e44-ad93-756ec85e94ac', 'c3605c89-d2ae-4d3f-b4b6-dc0078531c9e', 'migration-test-resource');
insert into role (role_id, resource_type_id, name) values ('11b3a386-70ef-4ef5-bc5e-e897cb2ca859', 'c3605c89-d2ae-4d3f-b4b6-dc0078531c9e', 'migration-test-role');
insert into identities (id, username, registration_completed) values ('7bb8876f-7d93-46ad-bbd3-733b77b76c55', 'migration-test-user', true);
insert into identity_role (identity_role_id, resource_id, identity_id, role_id) values ('977182c3-71b9-4954-bd58-834219d6441b', '9c17b0a3-a56e-4e44-ad93-756ec85e94ac', '7bb8876f-7d93-46ad-bbd3-733b77b76c55', '11b3a386-70ef-4ef5-bc5e-e897cb2ca859');

delete from identity_role where identity_role_id = '977182c3-71b9-4954-bd58-834219d6441b';
delete from identities where id = '7bb8876f-7d93-46ad-bbd3-733b77b76c55';
delete from role where role_id = '11b3a386-70ef-4ef5-bc5e-e897cb2ca859';
delete from resource where resource_id = '9c17b0a3-a56e-4e44-ad93-756ec85e94ac';
delete from resource_type where resource_type_id = 'c3605c89-d2ae-4d3f-b4b6-dc0078531c9e';