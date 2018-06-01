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

func (s *authorizationBlackBoxTest) TestAppendAssociation() {
	aID := uuid.NewV4()
	bID := uuid.NewV4()

	associations := []authorization.IdentityAssociation{}

	resourceNameFoo := "resource_foo"
	associations = authorization.AppendAssociation(associations, "foo", &resourceNameFoo, nil, &aID, true, nil)

	require.Equal(s.T(), 1, len(associations))
	require.Equal(s.T(), "foo", associations[0].ResourceID)
	require.Equal(s.T(), resourceNameFoo, associations[0].ResourceName)
	require.Equal(s.T(), aID, *associations[0].IdentityID)
	require.True(s.T(), associations[0].Member)
	require.Equal(s.T(), 0, len(associations[0].Roles))

	resourceNameBar := "resource_bar"
	roleName := "admin"
	associations = authorization.AppendAssociation(associations, "bar", &resourceNameBar, nil, &bID, false, &roleName)

	require.Equal(s.T(), 2, len(associations))

	found := false
	for _, assoc := range associations {
		if assoc.ResourceID == "bar" {
			found = true
			require.Equal(s.T(), resourceNameBar, assoc.ResourceName)
			require.Equal(s.T(), bID, *assoc.IdentityID)
			require.False(s.T(), assoc.Member)
			require.Equal(s.T(), 1, len(assoc.Roles))
			require.Equal(s.T(), roleName, assoc.Roles[0])
			break
		}
	}

	require.True(s.T(), found)

	roleName = "user"
	parentResourceID := uuid.NewV4().String()
	associations = authorization.AppendAssociation(associations, "bar", nil, &parentResourceID, nil, true, &roleName)
	require.Equal(s.T(), 2, len(associations))

	found = false
	for _, assoc := range associations {
		if assoc.ResourceID == "bar" {
			found = true
			require.Equal(s.T(), resourceNameBar, assoc.ResourceName)
			require.Equal(s.T(), bID, *assoc.IdentityID)
			require.True(s.T(), assoc.Member)
			require.Equal(s.T(), 2, len(assoc.Roles))
			require.NotNil(s.T(), assoc.ParentResourceID)
			require.Equal(s.T(), parentResourceID, *assoc.ParentResourceID)
			adminRoleFound := false
			userRoleFound := false
			for _, role := range assoc.Roles {
				if role == "admin" {
					adminRoleFound = true
				} else if role == "user" {
					userRoleFound = true
				}
			}
			require.True(s.T(), adminRoleFound)
			require.True(s.T(), userRoleFound)
			break
		}
	}
}

func (s *authorizationBlackBoxTest) TestMergeAssociations() {
	cID := uuid.NewV4()
	dID := uuid.NewV4()

	c := authorization.IdentityAssociation{
		IdentityID:   &cID,
		ResourceName: "resource_alpha",
		ResourceID:   "alpha",
		Member:       false,
		Roles:        []string{"user"},
	}

	d := authorization.IdentityAssociation{
		IdentityID:   &dID,
		ResourceName: "resource_bravo",
		ResourceID:   "bravo",
		Member:       false,
		Roles:        []string{"admin"},
	}

	e := authorization.IdentityAssociation{
		ResourceID: "alpha",
		Member:     true,
		Roles:      []string{"owner"},
	}

	associations := []authorization.IdentityAssociation{c}

	merge := []authorization.IdentityAssociation{d, e}

	associations = authorization.MergeAssociations(associations, merge)

	require.Len(s.T(), associations, 2)
	for _, assoc := range associations {
		if assoc.ResourceID == "alpha" {
			require.Len(s.T(), assoc.Roles, 2)
			userFound := false
			ownerFound := false
			for _, role := range assoc.Roles {
				if role == "owner" {
					ownerFound = true
				} else if role == "user" {
					userFound = true
				}
			}

			assert.True(s.T(), ownerFound, "owner role not found")
			assert.True(s.T(), userFound, "user role not found")
		}
	}
}

func (s *authorizationBlackBoxTest) TestScopeForManagingResourceType() {
	require.Equal(s.T(), authorization.ScopeForManagingRolesInResourceType(authorization.ResourceTypeSpace), authorization.ManageRoleAssignmentsInSpaceScope)
	require.Equal(s.T(), authorization.ScopeForManagingRolesInResourceType(authorization.IdentityResourceTypeOrganization), authorization.ManageOrganizationMembersScope)
	require.Equal(s.T(), authorization.ScopeForManagingRolesInResourceType(authorization.IdentityResourceTypeTeam), authorization.ManageTeamMembersScope)
	require.Equal(s.T(), authorization.ScopeForManagingRolesInResourceType(authorization.IdentityResourceTypeGroup), authorization.ManageSecurityGroupMembersScope)

	// test the default
	require.Equal(s.T(), authorization.ScopeForManagingRolesInResourceType(authorization.IdentityResourceTypeUser), authorization.ManageRoleAssignmentsInSpaceScope)
}
