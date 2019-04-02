-- index users on the 'banned' column to avoid fetching banned users during deactivation notification/execution
CREATE INDEX users_banned on users using btree (banned);
