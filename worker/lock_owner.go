package worker

import "context"

const (
	// LockOwner the contant to specify the name of the lock owner in the context
	LockOwner string = "lock_owner"
)

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
