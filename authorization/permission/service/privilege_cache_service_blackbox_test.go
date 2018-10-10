package service_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type privilegeCacheServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
}

func TestRunPrivilegeCacheServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &privilegeCacheServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *privilegeCacheServiceBlackBoxTest) SetupSuite() {
	s.DBTestSuite.SetupSuite()
}

func (s *privilegeCacheServiceBlackBoxTest) TestPrivilegeCache() {
	// Create a new resource type, with scopes "charlie" and "delta"
	rt := s.Graph.CreateResourceType()
	rt.AddScope("charlie")
	rt.AddScope("delta")

	// Create some roles for the new resource type
	charlieRole := s.Graph.CreateRole(rt)
	charlieRole.AddScope("charlie")
	deltaRole := s.Graph.CreateRole(rt)
	deltaRole.AddScope("delta")

	// Create a resource
	r := s.Graph.CreateResource(rt)

	// Create an identity
	id := s.Graph.CreateIdentity()

	// Assign charlieRole to the user for the resource
	s.Graph.CreateIdentityRole(r, id, charlieRole)

	// Retrieve the privilege cache for the identity/resource
	priv, err := s.Application.PrivilegeCacheService().CachedPrivileges(s.Ctx, id.Identity().ID, r.ResourceID())
	require.NoError(s.T(), err)

	// The privilege cache should not be stale
	require.False(s.T(), priv.Stale)

	// There should be exactly one scope
	require.Equal(s.T(), id.Identity().ID, priv.IdentityID)
	require.Equal(s.T(), r.ResourceID(), priv.ResourceID)
	require.Len(s.T(), priv.ScopesAsArray(), 1)
	require.Contains(s.T(), priv.ScopesAsArray(), "charlie")
	require.Equal(s.T(), priv.Scopes, "charlie")

	// Now assign delta role to the user also
	s.Graph.CreateIdentityRole(r, id, deltaRole)

	// Retrieve the privilege cache for the identity/resource
	priv, err = s.Application.PrivilegeCacheService().CachedPrivileges(s.Ctx, id.Identity().ID, r.ResourceID())
	require.NoError(s.T(), err)

	// This time there should be two scopes, "charlie" and "delta"
	require.Len(s.T(), priv.ScopesAsArray(), 2)
	require.Contains(s.T(), priv.ScopesAsArray(), "charlie")
	require.Contains(s.T(), priv.ScopesAsArray(), "delta")
}
