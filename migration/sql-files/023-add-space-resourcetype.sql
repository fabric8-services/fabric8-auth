-- create RESOURCE_TYPE for a SPACE type

INSERT INTO resource_type 
            (resource_type_id, 
             NAME, 
             created_at) 
VALUES     ('6422fda4-a0fa-4d3c-8b79-8061e5c05e12', 
            'openshift.io/resource/space', 
            Now()); 


-- create a role named 'collaborator'

INSERT INTO role 
            (role_id, 
             resource_type_id, 
             NAME, 
             created_at, 
             updated_at) 
VALUES     ('0e05e7fb-406c-4ba4-acc6-1eb290d45d02', 
            '6422fda4-a0fa-4d3c-8b79-8061e5c05e12', 
            'collaborator', 
            Now(), 
            Now()); 

-- create a scope that allows creation of workitems.

INSERT INTO resource_type_scope 
            (resource_type_scope_id, 
             resource_type_id, 
             NAME) 
VALUES     ('ab95b9d7-755a-4c25-8f78-ac1d613b59c9', 
            '6422fda4-a0fa-4d3c-8b79-8061e5c05e12', 
            'createWorkItem');


INSERT INTO role_scope 
            (scope_id, 
             role_id) 
VALUES     ('ab95b9d7-755a-4c25-8f78-ac1d613b59c9', 
            '0e05e7fb-406c-4ba4-acc6-1eb290d45d02'); 
