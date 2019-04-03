package repository

import (
	"context"
	"database/sql"
	"time"

	"cirello.io/pglock"
	"github.com/fabric8-services/fabric8-auth/log"
	errs "github.com/pkg/errors"
)

const (
	// LockOwner the contant to specify the name of the lock owner in the context
	LockOwner string = "lock_owner"
)

// LockRepository the interface for the repository
type LockRepository interface {
	AcquireLockToNotifyUsersToDeactivate(context.Context) (*pglock.Lock, error)
	AcquireLockToDeactivateUsers(context.Context) (*pglock.Lock, error)
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

// AcquireLockToDeactivateUsers acquires a lock on the postgres table for the requesting
// user deactivation worker
// Returns an error if the lock could not be obtained
func (r *lockRepositoryImpl) AcquireLockToDeactivateUsers(ctx context.Context) (*pglock.Lock, error) {
	return r.acquireLock(ctx, "user_deactivation_worker_lock")
}

// AcquireLockToNotifyUsersToDeactivate acquires a lock on the postgres table for the requesting
// user deactivation notification worker
// Returns an error if the lock could not be obtained
func (r *lockRepositoryImpl) AcquireLockToNotifyUsersToDeactivate(ctx context.Context) (*pglock.Lock, error) {
	return r.acquireLock(ctx, "user_deactivation_notification_worker_lock")
}

// AcquireLockToNotifyUsersToDeactivate acquires a lock on the postgres table for the requesting
// user deactivation notification worker
// Returns an error if the lock could not be obtained
func (r *lockRepositoryImpl) acquireLock(ctx context.Context, name string) (*pglock.Lock, error) {
	log.Info(ctx, map[string]interface{}{
		"lock":  name,
		"owner": GetLockOwner(ctx),
	}, "acquiring lock...")
	// obtain a lock to prevent other pods to perform this task
	c, err := pglock.New(r.db, lockOptions(ctx)...)
	if err != nil {
		return nil, errs.Wrap(err, "cannot create worker lock client")
	}
	l, err := c.Acquire(name, pglock.FailIfLocked()) // will fail if lock was already acquired
	if err != nil {
		return nil, errs.Wrapf(err, "cannot acquire worker lock '%s", name)
	}
	log.Info(ctx, map[string]interface{}{
		"lock":  name,
		"owner": GetLockOwner(ctx),
	}, "acquired lock")
	return l, nil
}

func lockOptions(ctx context.Context) []pglock.ClientOption {
	opts := []pglock.ClientOption{
		pglock.WithCustomTable("worker_lock"),
		pglock.WithLeaseDuration(3 * time.Second),
		pglock.WithHeartbeatFrequency(1 * time.Second),
	}
	if owner := GetLockOwner(ctx); owner != "" {
		opts = append(opts, pglock.WithOwner(owner))
	}
	return opts

}

// GetLockOwner return the owner to use when acquiring a lock.
// returns empty string if the given context did not contain
// any *string* value for the `lock_owner` key.
func GetLockOwner(ctx context.Context) string {
	if owner := ctx.Value(LockOwner); owner != nil {
		if owner, ok := owner.(string); ok {
			return owner
		}
	}
	return ""
}
