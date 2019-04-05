package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/fabric8-services/fabric8-auth/log"

	"cirello.io/pglock"
	errs "github.com/pkg/errors"
)

// LockRepository the interface for the repository
type LockRepository interface {
	AcquireLock(ctx context.Context, owner string, name string) (*pglock.Lock, error)
}

type lockRepositoryImpl struct {
	db *sql.DB
}

// NewLockRepository creates a new storage type.
func NewLockRepository(db *sql.DB) LockRepository {
	return &lockRepositoryImpl{
		db: db,
	}
}

// acquireLock acquires a lock with the given name for the given owner
// Returns an error if the lock could not be obtained
func (r *lockRepositoryImpl) AcquireLock(ctx context.Context, owner, name string) (*pglock.Lock, error) {
	log.Info(ctx, map[string]interface{}{
		"lock":  name,
		"owner": owner,
	}, "acquiring lock...")
	// obtain a lock to prevent other pods to perform this task
	opts := []pglock.ClientOption{
		pglock.WithCustomTable("worker_lock"),
		pglock.WithLeaseDuration(3 * time.Second),
		pglock.WithHeartbeatFrequency(1 * time.Second),
	}
	if owner != "" {
		// use a specific owner name, otherwise it will be a random value (default behaviour)
		opts = append(opts, pglock.WithOwner(owner))
	}
	c, err := pglock.New(r.db, opts...)
	if err != nil {
		return nil, errs.Wrap(err, "cannot create worker lock client")
	}
	l, err := c.Acquire(name, pglock.FailIfLocked()) // will fail if lock was already acquired
	if err != nil {
		return nil, errs.Wrapf(err, "cannot acquire worker lock '%s", name)
	}
	log.Info(ctx, map[string]interface{}{
		"lock":  name,
		"owner": owner,
	}, "acquired lock")
	return l, nil
}
