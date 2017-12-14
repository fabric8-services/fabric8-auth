ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT false;
UPDATE users SET email_verified = true;
ALTER TABLE users ALTER COLUMN email_verified set NOT NULL;


---
-- type VerificationCode struct {
--	gormsupport.Lifecycle
--	ID       uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key"` // This is the ID PK field
-- 	User     User
--	Verified bool // The verification status of the updated email.
--	Code     string
-- }
--


CREATE TABLE external_provider_tokens (
    id uuid primary key DEFAULT uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    user_id uuid REFERENCES users(id),
    verified boolean DEFAULT false,
    code text not null,
);




