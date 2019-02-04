-- create resource for admin-console

INSERT INTO resource 
            (resource_id, 
             resource_type_id, 
	     name,
             created_at) 
VALUES     ('77851e8f-2b9b-45dc-bbbd-bafef7af652b', 
            'f5dd9ef5-1bf6-4222-a844-9247ed961a1d', 
	    'admin_console',
            Now()); 


-- rename `user_admin` role to `admin_console_admin`

UPDATE role 
	SET name='admin_console_admin'
	WHERE role_id='2c993cbd-83f5-4e8c-858f-ca11bcf718b0'; 

