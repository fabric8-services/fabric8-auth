package migration

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"sync"
	"text/template"

	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/goadesign/goa/client"
	errs "github.com/pkg/errors"
)

// AdvisoryLockID is a random number that should be used within the application
// by anybody who wants to modify the "version" table.
const AdvisoryLockID = 42

// fn defines the type of function that can be part of a migration steps
type fn func(tx *sql.Tx) error

// steps defines a collection of all the functions that make up a version
type steps []fn

// Migrations defines all a collection of all the steps
type Migrations []steps

// mutex variable to lock/unlock the population of common types
var populateLocker = &sync.Mutex{}

type MigrationConfiguration interface {
	GetOpenShiftClientApiUrl() string
}

// Migrate executes the required migration of the database on startup.
// For each successful migration, an entry will be written into the "version"
// table, that states when a certain version was reached.
func Migrate(db *sql.DB, catalog string, configuration MigrationConfiguration) error {

	var err error
	if db == nil {
		return errs.Errorf("Database handle is nil\n")
	}

	m := GetMigrations(configuration)

	var tx *sql.Tx
	for nextVersion := int64(0); nextVersion < int64(len(m)) && err == nil; nextVersion++ {

		tx, err = db.Begin()
		if err != nil {
			return errs.Errorf("Failed to start transaction: %s\n", err)
		}

		err = MigrateToNextVersion(tx, &nextVersion, m, catalog)

		if err != nil {
			oldErr := err
			log.Info(nil, map[string]interface{}{
				"next_version": nextVersion,
				"migrations":   m,
				"err":          err,
			}, "Rolling back transaction due to: %v", err)

			if err = tx.Rollback(); err != nil {
				log.Error(nil, map[string]interface{}{
					"next_version": nextVersion,
					"migrations":   m,
					"err":          err,
				}, "error while rolling back transaction: ", err)
				return errs.Errorf("Error while rolling back transaction: %s\n", err)
			}
			return oldErr
		}

		if err = tx.Commit(); err != nil {
			log.Error(nil, map[string]interface{}{
				"migrations": m,
				"err":        err,
			}, "error during transaction commit: %v", err)
			return errs.Errorf("Error during transaction commit: %s\n", err)
		}

	}

	if err != nil {
		log.Error(nil, map[string]interface{}{
			"migrations": m,
			"err":        err,
		}, "migration failed with error: %v", err)
		return errs.Errorf("Migration failed with error: %s\n", err)
	}

	return nil
}

// GetMigrations returns the migrations all the migrations we have.
// Add your own migration to the end of this function.
// IMPORTANT: ALWAYS APPEND AT THE END AND DON'T CHANGE THE ORDER OF MIGRATIONS!
func GetMigrations(configuration MigrationConfiguration) Migrations {
	m := Migrations{}

	// Version 0
	m = append(m, steps{ExecuteSQLFile("000-bootstrap.sql")})

	// Version 1
	m = append(m, steps{ExecuteSQLFile("001-identities-users.sql")})

	// Version 2
	m = append(m, steps{ExecuteSQLFile("002-oauth-states.sql")})

	// Version 3
	m = append(m, steps{ExecuteSQLFile("003-space-resources.sql")})

	// Version 4

	m = append(m, steps{ExecuteSQLFile("004-unique-resource-space.sql")})

	// Version 5
	m = append(m, steps{ExecuteSQLFile("005-authorization.sql")})

	// Version 6
	m = append(m, steps{ExecuteSQLFile("006-external-provider.sql")})

	// Version 7
	m = append(m, steps{ExecuteSQLFile("007-external-provider-id-index.sql")})

	// Version 8
	m = append(m, steps{ExecuteSQLFile("008-rename-token-table.sql")})

	// Version 9
	m = append(m, steps{ExecuteSQLFile("009-external-token-hard-delete.sql")})

	// Version 10
	defaultCluster := configuration.GetOpenShiftClientApiUrl()
	m = append(m, steps{ExecuteSQLFile("010-add-cluster-to-user.sql", defaultCluster)})

	// Version 11
	m = append(m, steps{ExecuteSQLFile("011-add-username-to-external-token.sql")})

	// Version 12
	m = append(m, steps{ExecuteSQLFile("012-hide-email.sql")})

	// Version 13
	m = append(m, steps{ExecuteSQLFile("013-add-email-verified.sql")})

	// Version 14
	m = append(m, steps{ExecuteSQLFile("014-add-user-feature-level.sql")})

	// Version 15
	m = append(m, steps{ExecuteSQLFile("015-clear-resources-create-resource-types.sql")})

	// Version 16
	m = append(m, steps{ExecuteSQLFile("016-add-state-to-auth-state-reference.sql")})

	// Version 17
	m = append(m, steps{ExecuteSQLFile("017-feature-level-not-null.sql")})

	// Version 18
	m = append(m, steps{ExecuteSQLFile("018-convert-user-feature-level.sql")})

	// Version 19
	m = append(m, steps{ExecuteSQLFile("019-authorization-part-2.sql")})

	// Version 20
	m = append(m, steps{ExecuteSQLFile("020-add-response-mode-to-auth-state-reference.sql")})

	// Version 21
	m = append(m, steps{ExecuteSQLFile("021-organizations-list-create.sql")})

	// Version 22
	m = append(m, steps{ExecuteSQLFile("022-add-deprovisioned-to-user.sql")})

	// Version 23
	m = append(m, steps{ExecuteSQLFile("023-resource-type-index.sql")})

	// Version 24
	m = append(m, steps{ExecuteSQLFile("024-role-mapping-and-team-and-group-identities.sql")})

	// Version 25
	m = append(m, steps{ExecuteSQLFile("025-fix-feature-level.sql")})

	// Version 26
	m = append(m, steps{ExecuteSQLFile("026-identities-users-indexes.sql")})

	// Version 27
	m = append(m, steps{ExecuteSQLFile("027-invitations.sql")})

	// Version 28
	m = append(m, steps{ExecuteSQLFile("028-make-organization-names-unique.sql")})

	// Version 29
	m = append(m, steps{ExecuteSQLFile("029-add-space-resourcetype.sql")})

	// Version 30
	m = append(m, steps{ExecuteSQLFile("030-add-team-admin-role.sql")})

	// Version 31
	m = append(m, steps{ExecuteSQLFile("031-clean-up-roles-scopes.sql")})

	// Version 32
	m = append(m, steps{ExecuteSQLFile("032-invitation-code.sql")})

	// Version 33
	m = append(m, steps{ExecuteSQLFile("033-drop-space-resources.sql")})

	// Version 34
	m = append(m, steps{ExecuteSQLFile("034-rename-token-table.sql")})

	// Version 35
	m = append(m, steps{ExecuteSQLFile("035-unique_constraint_default_role_mapping.sql")})

	// Version 36
	m = append(m, steps{ExecuteSQLFile("036-invitation-redirect-url.sql")})

	// Version N
	//
	// In order to add an upgrade, simply append an array of MigrationFunc to the
	// the end of the "migrations" slice. The version numbers are determined by
	// the index in the array. The following code in comments show how you can
	// do a migration in 3 steps. If one of the steps fails, the others are not
	// executed.
	// If something goes wrong during the migration, all you need to do is return
	// an error that is not nil.

	/*
		m = append(m, steps{
			func(db *sql.Tx) error {
				// Execute random go code
				return nil
			},
			ExecuteSQLFile("YOUR_OWN_FILE.sql"),
			func(db *sql.Tx) error {
				// Execute random go code
				return nil
			},
		})
	*/

	return m
}

// ExecuteSQLFile loads the given filename from the packaged SQL files and
// executes it on the given database. Golang text/template module is used
// to handle all the optional arguments passed to the sql files
func ExecuteSQLFile(filename string, args ...string) fn {
	return func(db *sql.Tx) error {
		data, err := Asset(filename)
		if err != nil {
			return errs.Wrapf(err, "failed to find filename: %s", filename)
		}

		if len(args) > 0 {
			tmpl, err := template.New("sql").Parse(string(data))
			if err != nil {
				return errs.Wrap(err, "failed to parse SQL template")
			}
			var sqlScript bytes.Buffer
			writer := bufio.NewWriter(&sqlScript)

			err = tmpl.Execute(writer, args)
			if err != nil {
				return errs.Wrap(err, "failed to execute SQL template")
			}
			// We need to flush the content of the writer
			writer.Flush()

			_, err = db.Exec(sqlScript.String())
			if err != nil {
				log.Error(context.Background(), map[string]interface{}{
					"err": err,
				}, "failed to execute this query: \n\n%s\n\n", sqlScript.String())
			}

		} else {
			_, err = db.Exec(string(data))
			if err != nil {
				log.Error(context.Background(), map[string]interface{}{
					"err": err,
				}, "failed to execute this query: \n\n%s\n\n", string(data))
			}
		}

		return errs.WithStack(err)
	}
}

// MigrateToNextVersion migrates the database to the nextVersion.
// If the database is already at nextVersion or higher, the nextVersion
// will be set to the actual next version.
func MigrateToNextVersion(tx *sql.Tx, nextVersion *int64, m Migrations, catalog string) error {
	// Obtain exclusive transaction level advisory that doesn't depend on any table.
	// Once obtained, the lock is held for the remainder of the current transaction.
	// (There is no UNLOCK TABLE command; locks are always released at transaction end.)
	if _, err := tx.Exec("SELECT pg_advisory_xact_lock($1)", AdvisoryLockID); err != nil {
		return errs.Errorf("Failed to acquire lock: %s\n", err)
	}

	// Determine current version and adjust the outmost loop
	// iterator variable "version"
	currentVersion, err := getCurrentVersion(tx, catalog)
	if err != nil {
		return errs.WithStack(err)
	}
	*nextVersion = currentVersion + 1
	if *nextVersion >= int64(len(m)) {
		// No further updates to apply (this is NOT an error)
		log.Info(nil, map[string]interface{}{
			"next_version":    *nextVersion,
			"current_version": currentVersion,
		}, "Current version %d. Nothing to update.", currentVersion)
		return nil
	}

	log.Info(nil, map[string]interface{}{
		"next_version":    *nextVersion,
		"current_version": currentVersion,
	}, "Attempt to update DB to version %v", *nextVersion)

	// Apply all the updates of the next version
	for j := range m[*nextVersion] {
		if err := m[*nextVersion][j](tx); err != nil {
			return errs.Errorf("Failed to execute migration of step %d of version %d: %s\n", j, *nextVersion, err)
		}
	}

	if _, err := tx.Exec("INSERT INTO version(version) VALUES($1)", *nextVersion); err != nil {
		return errs.Errorf("Failed to update DB to version %d: %s\n", *nextVersion, err)
	}

	log.Info(nil, map[string]interface{}{
		"next_version":    *nextVersion,
		"current_version": currentVersion,
	}, "Successfully updated DB to version %v", *nextVersion)

	return nil
}

// getCurrentVersion returns the highest version from the version
// table or -1 if that table does not exist.
//
// Returning -1 simplifies the logic of the migration process because
// the next version is always the current version + 1 which results
// in -1 + 1 = 0 which is exactly what we want as the first version.
func getCurrentVersion(db *sql.Tx, catalog string) (int64, error) {
	query := `SELECT EXISTS(
				SELECT 1 FROM information_schema.tables
				WHERE table_catalog=$1
				AND table_name='version')`
	row := db.QueryRow(query, catalog)

	var exists bool
	if err := row.Scan(&exists); err != nil {
		return -1, errs.Errorf("Failed to scan if table \"version\" exists: %s\n", err)
	}

	if !exists {
		// table doesn't exist
		return -1, nil
	}

	row = db.QueryRow("SELECT max(version) as current FROM version")

	var current int64 = -1
	if err := row.Scan(&current); err != nil {
		return -1, errs.Errorf("Failed to scan max version in table \"version\": %s\n", err)
	}

	return current, nil
}

// NewMigrationContext aims to create a new goa context where to initialize the
// request and req_id context keys.
// NOTE: We need this function to initialize the goa.ContextRequest
func NewMigrationContext(ctx context.Context) context.Context {
	req := &http.Request{Host: "localhost"}
	params := url.Values{}
	ctx = goa.NewContext(ctx, nil, req, params)
	// set a random request ID for the context
	var reqID string
	ctx, reqID = client.ContextWithRequestID(ctx)

	log.Debug(ctx, nil, "Initialized the migration context with Request ID: %v", reqID)

	return ctx
}
