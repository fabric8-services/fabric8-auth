-- create RESOURCE_TYPE for SYSTEM type

INSERT INTO resource_type 
            (resource_type_id, 
             NAME, 
             created_at) 
VALUES     ('f5dd9ef5-1bf6-4222-a844-9247ed961a1d', 
            'openshift.io/resource/system', 
            Now()); 


-- create a role named 'admin_console_user' 


INSERT INTO role 
            (role_id, 
             resource_type_id, 
             NAME, 
             created_at, 
             updated_at) 
VALUES     ('c558b66f-f71c-4614-8109-c9fa8e30f559', 
            'f5dd9ef5-1bf6-4222-a844-9247ed961a1d', 
            'admin_console_user', 
            Now(), 
            Now()); 

-- create a role named 'user_admin' 


INSERT INTO role 
            (role_id, 
             resource_type_id, 
             NAME, 
             created_at, 
             updated_at) 
VALUES     ('2c993cbd-83f5-4e8c-858f-ca11bcf718b0', 
            'f5dd9ef5-1bf6-4222-a844-9247ed961a1d', 
            'user_admin', 
            Now(), 
            Now()); 


-- create a scope named access

INSERT INTO resource_type_scope 
            (resource_type_scope_id, 
             resource_type_id, 
             NAME) 
VALUES     ('ac95b9d7-755a-4c25-8f78-ac1d613b59c9', 
            'f5dd9ef5-1bf6-4222-a844-9247ed961a1d', 
            'access');


-- create a scope named manage_users

INSERT INTO resource_type_scope 
            (resource_type_scope_id, 
             resource_type_id, 
             NAME) 
VALUES     ('4c1c4790-c86c-4937-9223-ac054f6e1251', 
            'f5dd9ef5-1bf6-4222-a844-9247ed961a1d', 
            'manage_user');



-- add scope access to role admin_console_user

INSERT INTO role_scope 
            (scope_id, 
             role_id) 
VALUES     ('ac95b9d7-755a-4c25-8f78-ac1d613b59c9', 
            'c558b66f-f71c-4614-8109-c9fa8e30f559'); 


-- add scopes  'access', 'manage_users' to role 'user_admin'

INSERT INTO role_scope 
            (scope_id, 
             role_id) 
VALUES     ('ac95b9d7-755a-4c25-8f78-ac1d613b59c9', 
            '2c993cbd-83f5-4e8c-858f-ca11bcf718b0'); 


INSERT INTO role_scope 
            (scope_id, 
             role_id) 
VALUES     ('4c1c4790-c86c-4937-9223-ac054f6e1251', 
            '2c993cbd-83f5-4e8c-858f-ca11bcf718b0'); 
