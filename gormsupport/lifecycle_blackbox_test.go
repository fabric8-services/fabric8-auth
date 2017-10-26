package gormsupport_test

import (
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/convert"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/stretchr/testify/assert"
)

func TestLifecycleEqual(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)

	// Ensure Lifecyle implements the Equaler interface
	var _ convert.Equaler = gormsupport.Lifecycle{}
	var _ convert.Equaler = (*gormsupport.Lifecycle)(nil)

	now := time.Now()
	nowPlus := time.Now().Add(time.Duration(1000))

	a := gormsupport.Lifecycle{
		CreatedAt: now,
		UpdatedAt: now,
		DeletedAt: nil,
	}

	// Test for type difference
	b := convert.DummyEqualer{}
	assert.False(t, a.Equal(b))

	// Test CreateAt difference
	c := gormsupport.Lifecycle{
		CreatedAt: nowPlus,
		UpdatedAt: now,
		DeletedAt: nil,
	}
	assert.False(t, a.Equal(c))

	// Test UpdatedAt difference
	d := gormsupport.Lifecycle{
		CreatedAt: now,
		UpdatedAt: nowPlus,
		DeletedAt: nil,
	}
	assert.False(t, a.Equal(d))

	// Test DeletedAt (one is not nil, the other is) difference
	e := gormsupport.Lifecycle{
		CreatedAt: now,
		UpdatedAt: now,
		DeletedAt: &now,
	}
	assert.False(t, a.Equal(e))

	// Test DeletedAt (both are not nil) difference
	g := gormsupport.Lifecycle{
		CreatedAt: now,
		UpdatedAt: nowPlus,
		DeletedAt: &now,
	}
	h := gormsupport.Lifecycle{
		CreatedAt: now,
		UpdatedAt: nowPlus,
		DeletedAt: &nowPlus,
	}
	assert.False(t, g.Equal(h))

	// Test two lifecycles are equal
	i := gormsupport.Lifecycle{
		CreatedAt: now,
		UpdatedAt: now,
		DeletedAt: nil,
	}
	assert.True(t, a.Equal(i))
}
