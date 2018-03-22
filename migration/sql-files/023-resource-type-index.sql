-- avoid the sequence scan 
CREATE INDEX IF NOT EXISTS idx_name_rt_name ON resource_type(name);
