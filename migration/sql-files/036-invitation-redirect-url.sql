ALTER TABLE invitation
  ADD COLUMN success_redirect_url TEXT,
  ADD COLUMN failure_redirect_url TEXT;