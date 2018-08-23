package migration_test

import (
	"bufio"
	"bytes"
	"database/sql"
	"fmt"
	"html/template"
	logger "log"
	"testing"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	config "github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/migration"
	"github.com/fabric8-services/fabric8-auth/resource"

	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fn defines the type of function that can be part of a migration steps
type fn func(tx *sql.Tx) error

const (
	databaseName = "test"
)

var (
	conf       *config.ConfigurationData
	migrations migration.Migrations
	dialect    gorm.Dialect
	gormDB     *gorm.DB
	sqlDB      *sql.DB
)

func setupTest() {
	var err error
	conf, err = config.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}
	configurationString := fmt.Sprintf("host=%s port=%d user=%s password=%s sslmode=%s connect_timeout=%d",
		conf.GetPostgresHost(),
		conf.GetPostgresPort(),
		conf.GetPostgresUser(),
		conf.GetPostgresPassword(),
		conf.GetPostgresSSLMode(),
		conf.GetPostgresConnectionTimeout(),
	)

	db, err := sql.Open("postgres", configurationString)
	defer db.Close()
	if err != nil {
		panic(fmt.Errorf("Cannot connect to database: %s\n", err))
	}

	db.Exec("DROP DATABASE " + databaseName)

	_, err = db.Exec("CREATE DATABASE " + databaseName)
	if err != nil {
		panic(err)
	}

	migrations = migration.GetMigrations(conf)
}

func TestMigrations(t *testing.T) {
	resource.Require(t, resource.Database)

	setupTest()

	configurationString := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s connect_timeout=%d",
		conf.GetPostgresHost(),
		conf.GetPostgresPort(),
		conf.GetPostgresUser(),
		conf.GetPostgresPassword(),
		databaseName,
		conf.GetPostgresSSLMode(),
		conf.GetPostgresConnectionTimeout(),
	)
	var err error
	sqlDB, err = sql.Open("postgres", configurationString)
	defer sqlDB.Close()
	if err != nil {
		panic(fmt.Errorf("Cannot connect to DB: %s\n", err))
	}
	gormDB, err = gorm.Open("postgres", configurationString)
	defer gormDB.Close()
	if err != nil {
		panic(fmt.Errorf("Cannot connect to DB: %s\n", err))
	}
	dialect = gormDB.Dialect()
	dialect.SetDB(sqlDB)

	t.Run("TestMigration01", testMigration01)
	t.Run("TestMigration02", testMigration02)
	t.Run("TestMigration04", testMigration04)
	t.Run("TestMigration07", testMigration07)
	t.Run("TestMigration08", testMigration08)
	t.Run("TestMigration09", testMigration09)
	t.Run("TestMigration10", testMigration10)
	t.Run("TestMigration11", testMigration11)
	t.Run("TestMigration18", testMigration18)
	t.Run("TestMigration21", testMigration21)
	t.Run("TestMigration22", testMigration22)
	t.Run("TestMigration23", testMigration23)
	t.Run("TestMigration25ValidHits", testMigration25ValidHits)
	t.Run("TestMigration25ValidMiss", testMigration25ValidMiss)
	t.Run("TestMigration27", testMigration27)
	t.Run("TestMigration28", testMigration28)
	t.Run("TestMigration29", testMigration29)
	t.Run("TestMigration30", testMigration30)
	t.Run("TestMigration31", testMigration31)
	t.Run("TestMigration33", testMigration33)
	t.Run("TestMigration36", testMigration36)

	// Perform the migration
	if err := migration.Migrate(sqlDB, databaseName, conf); err != nil {
		t.Fatalf("Failed to execute the migration: %s\n", err)
	}
}

func testMigration01(t *testing.T) {
	migrateToVersion(sqlDB, migrations[:(2)], (2))
	require.True(t, dialect.HasColumn("identities", "registration_completed"))

	// add new rows and check if the new column has the default value
	assert.Nil(t, runSQLscript(sqlDB, "001-insert-identities-users.sql"))

	// check if ALL the existing rows & new rows have the default value
	rows, err := sqlDB.Query("SELECT registration_completed FROM identities")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var registration_completed bool
		err = rows.Scan(&registration_completed)
		require.NoError(t, err)
		assert.False(t, registration_completed)
	}
}

func testMigration02(t *testing.T) {
	migrateToVersion(sqlDB, migrations[:(3)], (3))

	assert.True(t, gormDB.HasTable("oauth_state_references"))
	assert.True(t, dialect.HasColumn("oauth_state_references", "referrer"))
	assert.True(t, dialect.HasColumn("oauth_state_references", "id"))

	assert.Nil(t, runSQLscript(sqlDB, "002-insert-oauth-states.sql"))
}

func testMigration04(t *testing.T) {
	migrateToVersion(sqlDB, migrations[:(5)], (5))

	assert.NotNil(t, runSQLscript(sqlDB, "004-insert-duplicate-space-resource.sql"))
}

func testMigration07(t *testing.T) {
	migrateToVersion(sqlDB, migrations[:(8)], (8))

	assert.True(t, dialect.HasIndex("external_provider_tokens", "idx_provider_id"))
}

func testMigration08(t *testing.T) {
	migrateToVersion(sqlDB, migrations[:(9)], (9))

	assert.True(t, dialect.HasTable("external_tokens"))
}

func testMigration09(t *testing.T) {
	migrateToVersion(sqlDB, migrations[:(10)], (10))

	assert.False(t, dialect.HasColumn("external_tokens", "deleted_at"))
}

func testMigration10(t *testing.T) {
	migrateToVersion(sqlDB, migrations[:(11)], (11))
	assert.True(t, dialect.HasColumn("users", "cluster"))
}

func testMigration11(t *testing.T) {
	migrateToVersion(sqlDB, migrations[:(12)], (12))

	assert.True(t, dialect.HasColumn("external_tokens", "username"))
}

func testMigration18(t *testing.T) {
	// given
	migrateToVersion(sqlDB, migrations[:(18)], 18)
	require.Nil(t, runSQLscript(sqlDB, "018-convert-user-feature-level.sql"))
	var featureLevel string
	stmt, err := sqlDB.Prepare("select feature_level from users where id = $1")
	require.NoError(t, err)
	err = stmt.QueryRow("00000000-0000-0000-0000-000000000001").Scan(&featureLevel)
	require.NoError(t, err)
	require.Equal(t, "nopreproduction", featureLevel)
	// when
	migrateToVersion(sqlDB, migrations[:(19)], 19)
	// then
	stmt2, err := sqlDB.Prepare("select feature_level from users where id = $1")
	err = stmt2.QueryRow("00000000-0000-0000-0000-000000000001").Scan(&featureLevel)
	require.NoError(t, err)
	require.Equal(t, "released", featureLevel)
}

func testMigration21(t *testing.T) {
	migrateToVersion(sqlDB, migrations[:(22)], (22))
	assert.Nil(t, runSQLscript(sqlDB, "021-test-organizations.sql"))

	rows, err := sqlDB.Query("SELECT name FROM resource_type WHERE name = $1", authorization.IdentityResourceTypeOrganization)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var resourceTypeName string
		err = rows.Scan(&resourceTypeName)
		require.Equal(t, authorization.IdentityResourceTypeOrganization, resourceTypeName)
	}
}

func testMigration22(t *testing.T) {

	// Before introducing deprovisioned field
	migrateToVersion(sqlDB, migrations[:(22)], (22))
	require.Nil(t, runSQLscript(sqlDB, "022-1-before-migration-deprovisioned-user.sql"))

	// After introducing deprovisioned field
	migrateToVersion(sqlDB, migrations[:(23)], (23))
	require.Nil(t, runSQLscript(sqlDB, "022-2-after-migration-deprovisioned-user.sql"))

	rows, err := sqlDB.Query("SELECT id FROM users WHERE deprovisioned IS TRUE")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	// Expecting only one deprovisioned user
	require.True(t, rows.Next())
	var id string
	err = rows.Scan(&id)
	require.Equal(t, "a83a4508-3303-441e-863a-84ff9e7f745a", id)
	require.False(t, rows.Next())
}

func testMigration23(t *testing.T) {
	migrateToVersion(sqlDB, migrations[:(24)], (24))
	assert.True(t, dialect.HasIndex("resource_type", "idx_name_rt_name"))
}

func testMigration29(t *testing.T) {

	migrateToVersion(sqlDB, migrations[:(30)], (30))

	countRows(t, "SELECT count(1) FROM role where  ( name = 'contributor' or name = 'viewer' or name = 'admin' ) and resource_type_id = '6422fda4-a0fa-4d3c-8b79-8061e5c05e12' group by resource_type_id", 3)
	countRows(t, "SELECT count(1) FROM resource_type_scope where ( name = 'view' or name = 'contribute' or name = 'manage' ) and resource_type_id = '6422fda4-a0fa-4d3c-8b79-8061e5c05e12' group by resource_type_id", 3)

	// for viewer
	countRows(t, "SELECT count(1) from role_scope where ( scope_id = 'ab95b9d7-755a-4c25-8f78-ac1d613b59c9' and role_id = 'f558b66f-f71c-4614-8109-c9fa8e30f559' )", 1)

	// for contributor
	countRows(t, "SELECT count(1) from role_scope where ( scope_id = 'ab95b9d7-755a-4c25-8f78-ac1d613b59c9' and role_id = '0e05e7fb-406c-4ba4-acc6-1eb290d45d02' )", 1)
	countRows(t, "SELECT count(1) from role_scope where ( scope_id = '07da9f1a-081e-479e-b070-495b3108f027' and role_id = '0e05e7fb-406c-4ba4-acc6-1eb290d45d02' )", 1)

	// for admin
	countRows(t, "SELECT count(1) from role_scope where ( scope_id = 'ab95b9d7-755a-4c25-8f78-ac1d613b59c9' and role_id = '2d993cbd-83f5-4e8c-858f-ca11bcf718b0' )", 1)
	countRows(t, "SELECT count(1) from role_scope where ( scope_id = '07da9f1a-081e-479e-b070-495b3108f027' and role_id = '2d993cbd-83f5-4e8c-858f-ca11bcf718b0' )", 1)
	countRows(t, "SELECT count(1) from role_scope where ( scope_id = '431c4790-c86f-4937-9223-ac054f6e1251' and role_id = '2d993cbd-83f5-4e8c-858f-ca11bcf718b0' )", 1)
}

func countRows(t *testing.T, sql string, expectedCount int) {
	var count int
	rows, err := sqlDB.Query(sql)
	defer rows.Close()
	if err != nil {
		t.Fatal(err)
	}
	require.True(t, rows.Next())
	err = rows.Scan(&count)
	require.Equal(t, expectedCount, count)
}

func testMigration25ValidHits(t *testing.T) {

	migrateToVersion(sqlDB, migrations[:(25)], (25))
	require.Nil(t, runSQLscript(sqlDB, "025-before-fix-feature-level.sql"))

	migrateToVersion(sqlDB, migrations[:(26)], (26))

	rows, err := sqlDB.Query("SELECT feature_level FROM users WHERE email = 'migration-test-1025+preview@mail.com'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	require.True(t, rows.Next())
	var featureLevel string
	err = rows.Scan(&featureLevel)
	require.Equal(t, account.DefaultFeatureLevel, featureLevel)

}

func testMigration25ValidMiss(t *testing.T) {

	rows, err := sqlDB.Query("SELECT feature_level FROM users WHERE email = 'migration-test-1027+preview@mail.com'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	require.True(t, rows.Next())
	var featureLevel string
	err = rows.Scan(&featureLevel)
	// doesn't change.
	require.Equal(t, "somethingelse", featureLevel)

}

func testMigration27(t *testing.T) {
	migrateToVersion(sqlDB, migrations[:(28)], (28))

	// Confirm that the manage_members scope was added
	rows, err := sqlDB.Query("SELECT resource_type_scope_id FROM resource_type_scope rts, resource_type rt WHERE rts.resource_type_id = rt.resource_type_id AND rt.name = 'identity/organization' AND rts.name = 'manage_members'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	require.True(t, rows.Next())
	var resourceTypeScopeID uuid.UUID
	err = rows.Scan(&resourceTypeScopeID)

	// Now confirm that the scope has been assigned to the organization 'owner' role
	rows, err = sqlDB.Query("SELECT r.name FROM role r, role_scope rs WHERE r.role_id = rs.role_id AND rs.scope_id = $1", resourceTypeScopeID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	require.True(t, rows.Next())
	var roleName string
	err = rows.Scan(&roleName)

	require.Equal(t, "owner", roleName)

	// Create some test data
	require.Nil(t, runSQLscript(sqlDB, "026-insert-test-invitation-data.sql"))

	// Confirm that we can create an invitation for an organization
	_, err = sqlDB.Exec("INSERT INTO invitation (invitation_id, invite_to, identity_id, member) VALUES (uuid_generate_v4(), 'c62d77b2-194c-47d0-8bbf-b1308576876d', 'd9161547-5263-4c83-a729-e39ff088978e', true)")
	if err != nil {
		t.Fatal(err)
	}

	// Confirm that we can create an invitation for a resource
	_, err = sqlDB.Exec("INSERT INTO invitation (invitation_id, resource_id, identity_id, member) VALUES (uuid_generate_v4(), 'c6a2ee2e-7ec6-4c04-ae7e-5ff8c36b28b9', 'd9161547-5263-4c83-a729-e39ff088978e', false)")
	if err != nil {
		t.Fatal(err)
	}

	// Confirm that we get a check constraint violation if we try to provide both invite_to and resource_id values
	_, err = sqlDB.Exec("INSERT INTO invitation (invitation_id, invite_to, resource_id, identity_id, member) VALUES (uuid_generate_v4(), 'c62d77b2-194c-47d0-8bbf-b1308576876d', 'c6a2ee2e-7ec6-4c04-ae7e-5ff8c36b28b9', 'd9161547-5263-4c83-a729-e39ff088978e', false)")
	require.NotNil(t, err)

	// Cleanup the test data
	require.Nil(t, runSQLscript(sqlDB, "026-cleanup-test-invitation-data.sql"))
}

func testMigration28(t *testing.T) {
	migrateToVersion(sqlDB, migrations[:(28)], (28))

	var orgResourceTypeID string
	err := sqlDB.QueryRow("SELECT resource_type_id FROM resource_type WHERE name = 'identity/organization'").Scan(&orgResourceTypeID)
	require.NoError(t, err)

	// Let's create two organization resources with the same name
	_, err = sqlDB.Exec("INSERT INTO resource (resource_id, resource_type_id, name, created_at) VALUES ('ca9dfe76-d5f2-4f0c-b887-ad722e745cd5', $1, 'Acme Corporation', now())", orgResourceTypeID)
	require.NoError(t, err)

	_, err = sqlDB.Exec("INSERT INTO resource (resource_id, resource_type_id, name, created_at) VALUES ('3ac75b8a-e794-403b-bf1b-e0516af99a93', $1, 'Acme Corporation', now())", orgResourceTypeID)
	require.NoError(t, err)

	migrateToVersion(sqlDB, migrations[:(29)], (29))

	// Let's check the name of our first resource, it should be the same
	var resourceName string
	err = sqlDB.QueryRow("SELECT name FROM resource WHERE resource_id = 'ca9dfe76-d5f2-4f0c-b887-ad722e745cd5'").Scan(&resourceName)
	require.NoError(t, err)
	require.Equal(t, "Acme Corporation", resourceName)

	// Our other resource should have been renamed though
	err = sqlDB.QueryRow("SELECT name FROM resource WHERE resource_id = '3ac75b8a-e794-403b-bf1b-e0516af99a93'").Scan(&resourceName)
	require.NoError(t, err)
	require.Equal(t, "Acme Corporation (1)", resourceName)

	// After update 28 it should be impossible to create organizations with duplicate names
	orgName := "Acme" + uuid.NewV4().String()
	_, err = sqlDB.Exec("INSERT INTO resource (resource_id, resource_type_id, name) VALUES (uuid_generate_v4(), '66659ea9-aa0a-4737-96e2-e96e615dc280', $1)", orgName)
	require.NoError(t, err)

	// This one should fail
	_, err = sqlDB.Exec("INSERT INTO resource (resource_id, resource_type_id, name) VALUES (uuid_generate_v4(), '66659ea9-aa0a-4737-96e2-e96e615dc280', $1)", orgName)
	require.Error(t, err)
}

func testMigration30(t *testing.T) {
	migrateToVersion(sqlDB, migrations[:(31)], (31))

	var teamResourceTypeID string
	err := sqlDB.QueryRow("SELECT resource_type_id FROM resource_type WHERE name = 'identity/team'").Scan(&teamResourceTypeID)
	require.NoError(t, err)

	var scopeName string
	err = sqlDB.QueryRow("SELECT name FROM resource_type_scope WHERE resource_type_scope_id = $1 AND resource_type_id = $2", "45cc3446-6afe-4758-82bb-41141e1783ce", teamResourceTypeID).Scan(&scopeName)
	require.NoError(t, err)
	require.Equal(t, authorization.ManageTeamsInSpaceScope, scopeName)

	countRows(t, "SELECT count(*) FROM role_scope WHERE ( scope_id = '45cc3446-6afe-4758-82bb-41141e1783ce' and role_id = '4e03c5df-d3f6-4665-9ffa-4bef05355744' )", 1)
}

func testMigration31(t *testing.T) {
	migrateToVersion(sqlDB, migrations[:(32)], (32))

	var roleID uuid.UUID
	err := sqlDB.QueryRow("SELECT r.role_id FROM role r, resource_type rt WHERE r.name = 'admin' AND r.resource_type_id = rt.resource_type_id AND rt.name = 'identity/organization'").Scan(&roleID)
	require.NoError(t, err)

	var resourceTypeScopeID uuid.UUID
	err = sqlDB.QueryRow("SELECT s.resource_type_scope_id FROM resource_type_scope s, resource_type rt WHERE s.name = 'manage' AND s.resource_type_id = rt.resource_type_id AND rt.name = 'identity/organization'").Scan(&resourceTypeScopeID)
	require.NoError(t, err)

	countRows(t, "SELECT count(role_id) FROM role WHERE role_id = '4e03c5df-d3f6-4665-9ffa-4bef05355744'", 0)
	countRows(t, "SELECT count(resource_type_scope_id) FROM resource_type_scope WHERE name = 'manage' AND resource_type_id = (SELECT resource_type_id FROM resource_type WHERE name = 'identity/team')", 0)
}

func testMigration33(t *testing.T) {
	migrateToVersion(sqlDB, migrations[:(34)], (34))
	assert.False(t, dialect.HasTable("space_resources"))
}

func testMigration36(t *testing.T) {
	migrateToVersion(sqlDB, migrations[:(37)], (37))
	assert.True(t, dialect.HasColumn("privilege_cache", "scopes"))
	assert.True(t, dialect.HasColumn("privilege_cache", "stale"))
}

// runSQLscript loads the given filename from the packaged SQL test files and
// executes it on the given database. Golang text/template module is used
// to handle all the optional arguments passed to the sql test files
func runSQLscript(db *sql.DB, sqlFilename string) error {
	var tx *sql.Tx
	tx, err := db.Begin()
	if err != nil {
		return errs.New(fmt.Sprintf("Failed to start transaction: %s\n", err))
	}
	if err := executeSQLTestFile(sqlFilename)(tx); err != nil {
		log.Warn(nil, nil, "Failed to execute data insertion using '%s': %s\n", sqlFilename, err)
		if err = tx.Rollback(); err != nil {
			return errs.New(fmt.Sprintf("error while rolling back transaction: %s", err))
		}
	}
	if err = tx.Commit(); err != nil {
		return errs.New(fmt.Sprintf("Error during transaction commit: %s\n", err))
	}

	return nil
}

// executeSQLTestFile loads the given filename from the packaged SQL files and
// executes it on the given database. Golang text/template module is used
// to handle all the optional arguments passed to the sql test files
func executeSQLTestFile(filename string, args ...string) fn {
	return func(db *sql.Tx) error {
		log.Info(nil, nil, "Executing SQL test script '%s'", filename)
		data, err := Asset(filename)
		if err != nil {
			return errs.WithStack(err)
		}

		if len(args) > 0 {
			tmpl, err := template.New("sql").Parse(string(data))
			if err != nil {
				return errs.WithStack(err)
			}
			var sqlScript bytes.Buffer
			writer := bufio.NewWriter(&sqlScript)
			err = tmpl.Execute(writer, args)
			if err != nil {
				return errs.WithStack(err)
			}
			// We need to flush the content of the writer
			writer.Flush()
			_, err = db.Exec(sqlScript.String())
		} else {
			_, err = db.Exec(string(data))
		}

		return errs.WithStack(err)
	}
}

// migrateToVersion runs the migration of all the scripts to a certain version
func migrateToVersion(db *sql.DB, m migration.Migrations, version int64) {
	var err error
	for nextVersion := int64(0); nextVersion < version && err == nil; nextVersion++ {
		var tx *sql.Tx
		tx, err = sqlDB.Begin()
		if err != nil {
			panic(fmt.Errorf("Failed to start transaction: %s\n", err))
		}

		if err = migration.MigrateToNextVersion(tx, &nextVersion, m, databaseName); err != nil {
			if err = tx.Rollback(); err != nil {
				logger.Fatalf("error while rolling back transaction: %v", err)
			}
			logger.Fatalf("Failed to migrate to version after rolling back")
		}

		if err = tx.Commit(); err != nil {
			logger.Fatalf("Error during transaction commit: %s", err)
		}
	}
}
