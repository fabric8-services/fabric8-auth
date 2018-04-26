-- create RESOURCE_TYPE for a SPACE type

INSERT INTO resource_type 
            (resource_type_id, 
             NAME, 
             created_at) 
VALUES     ('6422fda4-a0fa-4d3c-8b79-8061e5c05e12', 
            'openshift.io/resource/space', 
            Now()); 


-- create a role named 'contributor'

INSERT INTO role 
            (role_id, 
             resource_type_id, 
             NAME, 
             created_at, 
             updated_at) 
VALUES     ('0e05e7fb-406c-4ba4-acc6-1eb290d45d02', 
            '6422fda4-a0fa-4d3c-8b79-8061e5c05e12', 
            'contributor', 
            Now(), 
            Now()); 

-- create a role named 'viewer' 


INSERT INTO role 
            (role_id, 
             resource_type_id, 
             NAME, 
             created_at, 
             updated_at) 
VALUES     ('f558b66f-f71c-4614-8109-c9fa8e30f559', 
            '6422fda4-a0fa-4d3c-8b79-8061e5c05e12', 
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
VALUES     ('2d993cbd-83f5-4e8c-858f-ca11bcf718b0', 
            '6422fda4-a0fa-4d3c-8b79-8061e5c05e12', 
            'admin', 
            Now(), 
            Now()); 

-- create a scope named view


INSERT INTO resource_type_scope 
            (resource_type_scope_id, 
             resource_type_id, 
             NAME) 
VALUES     ('ab95b9d7-755a-4c25-8f78-ac1d613b59c9', 
            '6422fda4-a0fa-4d3c-8b79-8061e5c05e12', 
            'view');

-- create a scope named 'contribute'

INSERT INTO resource_type_scope 
            (resource_type_scope_id, 
             resource_type_id, 
             NAME) 
VALUES     ('07da9f1a-081e-479e-b070-495b3108f027', 
            '6422fda4-a0fa-4d3c-8b79-8061e5c05e12', 
            'contribute');



INSERT INTO resource_type_scope 
            (resource_type_scope_id, 
             resource_type_id, 
             NAME) 
VALUES     ('431c4790-c86f-4937-9223-ac054f6e1251', 
            '6422fda4-a0fa-4d3c-8b79-8061e5c05e12', 
            'manage');



-- add view to viewer

INSERT INTO role_scope 
            (scope_id, 
             role_id) 
VALUES     ('ab95b9d7-755a-4c25-8f78-ac1d613b59c9', 
            'f558b66f-f71c-4614-8109-c9fa8e30f559'); 



-- add view,contribute 

INSERT INTO role_scope 
            (scope_id, 
             role_id) 
VALUES     ('ab95b9d7-755a-4c25-8f78-ac1d613b59c9', 
            '0e05e7fb-406c-4ba4-acc6-1eb290d45d02'); 


INSERT INTO role_scope 
            (scope_id, 
             role_id) 
VALUES     ('07da9f1a-081e-479e-b070-495b3108f027', 
            '0e05e7fb-406c-4ba4-acc6-1eb290d45d02'); 

-- add view, contribute, manage

INSERT INTO role_scope 
            (scope_id, 
             role_id) 
VALUES     ('ab95b9d7-755a-4c25-8f78-ac1d613b59c9', 
            '2d993cbd-83f5-4e8c-858f-ca11bcf718b0'); 

INSERT INTO role_scope 
            (scope_id, 
             role_id) 
VALUES     ('07da9f1a-081e-479e-b070-495b3108f027', 
            '2d993cbd-83f5-4e8c-858f-ca11bcf718b0'); 

INSERT INTO role_scope 
            (scope_id, 
             role_id) 
VALUES     ('431c4790-c86f-4937-9223-ac054f6e1251', 
            '2d993cbd-83f5-4e8c-858f-ca11bcf718b0'); 
