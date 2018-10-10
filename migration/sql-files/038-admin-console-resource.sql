-- create RESOURCE_TYPE for a SPACE type

INSERT INTO resource_type 
            (resource_type_id, 
             NAME, 
             created_at) 
VALUES     ('f5dd9ef5-1bf6-4222-a844-9247ed961a1d', 
            'openshift.io/resource/system', 
            Now()); 


-- create a role named 'viewer' 


INSERT INTO role 
            (role_id, 
             resource_type_id, 
             NAME, 
             created_at, 
             updated_at) 
VALUES     ('c558b66f-f71c-4614-8109-c9fa8e30f559', 
            'f5dd9ef5-1bf6-4222-a844-9247ed961a1d', 
            'viewer', 
            Now(), 
            Now()); 

-- create a role named 'admin' 


INSERT INTO role 
            (role_id, 
             resource_type_id, 
             NAME, 
             created_at, 
             updated_at) 
VALUES     ('2c993cbd-83f5-4e8c-858f-ca11bcf718b0', 
            'f5dd9ef5-1bf6-4222-a844-9247ed961a1d', 
            'admin', 
            Now(), 
            Now()); 


-- create a scope named view

INSERT INTO resource_type_scope 
            (resource_type_scope_id, 
             resource_type_id, 
             NAME) 
VALUES     ('ac95b9d7-755a-4c25-8f78-ac1d613b59c9', 
            'f5dd9ef5-1bf6-4222-a844-9247ed961a1d', 
            'view');


-- create a scope named manage

INSERT INTO resource_type_scope 
            (resource_type_scope_id, 
             resource_type_id, 
             NAME) 
VALUES     ('4c1c4790-c86c-4937-9223-ac054f6e1251', 
            'f5dd9ef5-1bf6-4222-a844-9247ed961a1d', 
            'manage');



-- add scope view to role viewer

INSERT INTO role_scope 
            (scope_id, 
             role_id) 
VALUES     ('ac95b9d7-755a-4c25-8f78-ac1d613b59c9', 
            'c558b66f-f71c-4614-8109-c9fa8e30f559'); 


-- add scopes  'view', 'manage' to role 'admin'

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
