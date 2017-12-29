-- Create Oauth state reference table for states used in oauth workflow
CREATE TABLE oauth_state_references (
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    id varchar primary key DEFAULT CAST(uuid_generate_v4() AS varchar(50)) NOT NULL,
    referrer text NOT NULL
);