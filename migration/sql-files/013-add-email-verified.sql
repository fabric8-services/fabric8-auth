ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT false;
UPDATE users SET email_verified = true;
ALTER TABLE users ALTER COLUMN email_verified set NOT NULL;

CREATE TABLE verification_codes (
    id uuid primary key DEFAULT uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    user_id uuid REFERENCES users(id),
    code text
);

CREATE INDEX idx_user_id ON verification_codes (user_id);
CREATE INDEX idx_verification_code ON verification_codes (code);

