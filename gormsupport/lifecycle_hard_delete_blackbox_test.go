package gormsupport_test

import (
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/convert"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/resource"

	"github.com/stretchr/testify/assert"
)

func TestLifecycleHardDeleteEqual(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)

	// Ensure LifecycleHardDelete implements the Equaler interface
	var _ convert.Equaler = gormsupport.LifecycleHardDelete{}
	var _ convert.Equaler = (*gormsupport.LifecycleHardDelete)(nil)

	now := time.Now()
	nowPlus := time.Now().Add(time.Duration(1000))

	a := gormsupport.LifecycleHardDelete{
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Test for type difference
	b := convert.DummyEqualer{}
	assert.False(t, a.Equal(b))

	// Test CreateAt difference
	c := gormsupport.LifecycleHardDelete{
		CreatedAt: nowPlus,
		UpdatedAt: now,
	}
	assert.False(t, a.Equal(c))

	// Test UpdatedAt difference
	d := gormsupport.LifecycleHardDelete{
		CreatedAt: now,
		UpdatedAt: nowPlus,
	}
	assert.False(t, a.Equal(d))

	// Test two lifecycles are equal
	e := gormsupport.LifecycleHardDelete{
		CreatedAt: now,
		UpdatedAt: now,
	}
	assert.True(t, a.Equal(e))
}
