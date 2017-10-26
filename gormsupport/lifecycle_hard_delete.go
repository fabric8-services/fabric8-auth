package gormsupport

import (
	"time"

	"github.com/fabric8-services/fabric8-auth/convert"
	"github.com/jinzhu/gorm"
)

// LifecycleHardDelete struct contains all the items from gorm.Model except the ID and DeletedAt field,
// hence we can embed the LifecycleHardDelete struct into Models that needs hard delete and alike.
type LifecycleHardDelete struct {
	CreatedAt time.Time
	UpdatedAt time.Time
}

func init() {
	oldFunc := gorm.NowFunc
	// we use microsecond precision timestamps in the db, so also use ms precision timestamps in gorm callbacks.
	gorm.NowFunc = func() time.Time {
		return oldFunc().Round(time.Microsecond)
	}
}

// Equal returns true if two LifecycleHardDelete objects are equal; otherwise false is returned.
func (lc LifecycleHardDelete) Equal(u convert.Equaler) bool {
	other, ok := u.(LifecycleHardDelete)
	return ok && lc.CreatedAt.Equal(other.CreatedAt) && lc.UpdatedAt.Equal(other.UpdatedAt)
}
