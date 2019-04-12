CREATE TABLE worker_lock (
	name CHARACTER VARYING(255) PRIMARY KEY,
	record_version_number BIGINT,
	data BYTEA,
	owner CHARACTER VARYING(255)
);

CREATE SEQUENCE worker_lock_rvn OWNED BY worker_lock.record_version_number;