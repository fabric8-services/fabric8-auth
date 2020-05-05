-- 2 "old" oauth state refs
insert into oauth_state_references (created_at, referrer, state) values (now() - interval '3 days', 'foo1', 'bar1');
insert into oauth_state_references (created_at, referrer, state) values (now() - interval '2 days', 'foo2', 'bar2');
-- 1 "new" oauth state ref
insert into oauth_state_references (created_at, referrer, state) values (now()                    , 'foo3', 'bar3');