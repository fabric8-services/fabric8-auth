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
	GetLock(ctx context.Context, name string) (*pglock.Lock, error)
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

// AcquireLock acquires a lock with the given name for the given owner
// Returns an error if the lock could not be obtained
func (r *lockRepositoryImpl) AcquireLock(ctx context.Context, owner, name string) (*pglock.Lock, error) {
	log.Info(ctx, map[string]interface{}{
		"lock":  name,
		"owner": owner,
	}, "acquiring lock...")
	// obtain a lock to prevent other pods to perform this task
	opts := []pglock.ClientOption{
		pglock.WithCustomTable("worker_lock"),
		pglock.WithLeaseDuration(30 * time.Second),
		pglock.WithHeartbeatFrequency(10 * time.Second),
		pglock.WithLogger(log.Logger()),
	}
	if owner != "" {
		// use a specific owner name, otherwise it will be a random value (default behaviour)
		opts = append(opts, pglock.WithOwner(owner))
	}
	c, err := pglock.New(r.db, opts...)
	if err != nil {
		return nil, errs.Wrap(err, "cannot create worker lock client")
	}
	l, err := c.Acquire(name) // will wait until it succeeds
	if err != nil {
		// Try to get the name of the owner who holds the lock if any
		var holdByOwner string
		existingLock, nerr := c.Get(name)
		if nerr != nil {
			log.Error(ctx, map[string]interface{}{
				"err":   nerr,
				"lock":  name,
				"owner": owner,
			}, "cannot obtain the existing lock when trying to acquire a new one")
		} else {
			holdByOwner = existingLock.Owner()
		}
		return nil, errs.Wrapf(err, "cannot acquire worker lock '%s' which is currently hold by '%s'", name, holdByOwner)
	}
	log.Info(ctx, map[string]interface{}{
		"lock":  name,
		"owner": owner,
	}, "acquired lock")
	return l, nil
}

// GetLock returns the lock object from the given name in the table without holding
// it first.
func (r *lockRepositoryImpl) GetLock(ctx context.Context, name string) (*pglock.Lock, error) {
	log.Debug(ctx, map[string]interface{}{
		"lock": name,
	}, "obtaining existing lock...")
	opts := []pglock.ClientOption{
		pglock.WithCustomTable("worker_lock"),
		pglock.WithLogger(log.Logger()),
	}
	c, err := pglock.New(r.db, opts...)
	if err != nil {
		return nil, errs.Wrap(err, "cannot create worker lock client")
	}
	l, err := c.Get(name)
	if err != nil {
		return nil, errs.Wrapf(err, "cannot obtain the lock '%s'", name)
	}
	log.Debug(ctx, map[string]interface{}{
		"lock": name,
	}, "obtained existing lock")
	return l, nil
}
