package authorization_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type authorizationBlackBoxTest struct {
	gormtestsupport.DBTestSuite
}

func TestRunAuthorizationBlackBoxTest(t *testing.T) {
	suite.Run(t, &authorizationBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *authorizationBlackBoxTest) TestCanHaveMembers() {
	require.True(s.T(), authorization.CanHaveMembers(authorization.IdentityResourceTypeOrganization))
	require.True(s.T(), authorization.CanHaveMembers(authorization.IdentityResourceTypeTeam))
	require.True(s.T(), authorization.CanHaveMembers(authorization.IdentityResourceTypeGroup))
}

func (s *authorizationBlackBoxTest) TestMergeIdentityAssociations() {
	aID := uuid.NewV4()
	bID := uuid.NewV4()
	cID := uuid.NewV4()
	dID := uuid.NewV4()

	a := authorization.IdentityAssociation{
		IdentityID:   &aID,
		ResourceName: "resource_foo",
		ResourceID:   "foo",
		Member:       false,
		Roles:        []string{},
	}

	b := authorization.IdentityAssociation{
		IdentityID:   &bID,
		ResourceName: "resource_bar",
		ResourceID:   "bar",
		Member:       false,
		Roles:        []string{"admin"},
	}

	associations := []authorization.IdentityAssociation{a, b}

	c := authorization.IdentityAssociation{
		IdentityID:   &cID,
		ResourceName: "resource_alpha",
		ResourceID:   "alpha",
		Member:       false,
		Roles:        []string{},
	}

	d := authorization.IdentityAssociation{
		IdentityID:   &dID,
		ResourceName: "resource_bravo",
		ResourceID:   "bravo",
		Member:       false,
		Roles:        []string{"admin"},
	}

	e := authorization.IdentityAssociation{
		ResourceID: "bar",
		Member:     true,
		Roles:      []string{"owner"},
	}

	merge := []authorization.IdentityAssociation{c, d, e}

	associations = authorization.MergeAssociations(associations, merge)

	require.Equal(s.T(), 4, len(associations))
	for _, assoc := range associations {
		if assoc.ResourceID == "bar" {
			require.Equal(s.T(), 2, len(assoc.Roles))
			adminFound := false
			ownerFound := false
			for _, role := range assoc.Roles {
				if role == "admin" {
					adminFound = true
				} else if role == "owner" {
					ownerFound = true
				}
			}

			assert.True(s.T(), adminFound, "admin role not found")
			assert.True(s.T(), ownerFound, "owner role not found")
		}
	}
}
