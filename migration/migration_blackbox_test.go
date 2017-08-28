package migration_test

import (
	"bufio"
	"bytes"
	"database/sql"
	"fmt"
	"html/template"
	logger "log"
	"testing"

	config "github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/migration"
	"github.com/fabric8-services/fabric8-auth/resource"

	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
	errs "github.com/pkg/errors"
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

	migrations = migration.GetMigrations()
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

	// Perform the migration
	if err := migration.Migrate(sqlDB, databaseName); err != nil {
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
		assert.True(t, registration_completed == false)
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
