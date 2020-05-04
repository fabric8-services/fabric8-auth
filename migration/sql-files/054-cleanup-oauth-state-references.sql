-- deletes all oauth state references older created more than 24 hours ago
delete from oauth_state_references where created_at < current_timestamp - interval '1 day';