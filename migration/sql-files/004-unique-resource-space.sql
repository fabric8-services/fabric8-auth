-- Delete duplicate space resources in existence and keep only one
-- See https://wiki.postgresql.org/wiki/Deleting_duplicates
DELETE FROM space_resources
WHERE id IN (
  SELECT id
  FROM (
         SELECT id, ROW_NUMBER() OVER (partition BY space_id ORDER BY id) AS rnum
         FROM space_resources
       ) t
  WHERE t.rnum > 1
);

-- Recreate resources spaces ID index as unique to insure there is only one resource per space
DROP INDEX space_resources_space_id_idx;
CREATE UNIQUE INDEX space_resources_space_id_idx ON space_resources USING BTREE (space_id);