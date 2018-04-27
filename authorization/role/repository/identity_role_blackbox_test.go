package repository_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type identityRoleBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo                  role.IdentityRoleRepository
	identityRepo          account.IdentityRepository
	resourceRepo          resource.ResourceRepository
	resourceTypeRepo      resourcetype.ResourceTypeRepository
	resourceTypeScopeRepo resourcetype.ResourceTypeScopeRepository
	roleRepo              role.RoleRepository
}

func TestRunIdentityRoleBlackBoxTest(t *testing.T) {
	suite.Run(t, &identityRoleBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *identityRoleBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.DB.LogMode(true)
	s.repo = role.NewIdentityRoleRepository(s.DB)
	s.identityRepo = account.NewIdentityRepository(s.DB)
	s.resourceTypeRepo = resourcetype.NewResourceTypeRepository(s.DB)
	s.resourceTypeScopeRepo = resourcetype.NewResourceTypeScopeRepository(s.DB)
	s.roleRepo = role.NewRoleRepository(s.DB)
}

func (s *identityRoleBlackBoxTest) TestOKToDelete() {
	// create 2 identity roles, where the first one would be deleted.
	identityRole := createAndLoadIdentityRole(s)
	createAndLoadIdentityRole(s)

	err := s.repo.Delete(s.Ctx, identityRole.IdentityRoleID)
	assert.Nil(s.T(), err)

	// lets see how many are present.
	identityRoles, err := s.repo.List(s.Ctx)
	require.Nil(s.T(), err, "Could not list identity roles")
	require.True(s.T(), len(identityRoles) > 0)

	for _, data := range identityRoles {
		// The role 'role' was deleted and rest were not deleted, hence we check
		// that none of the role objects returned include the one deleted.
		require.NotEqual(s.T(), identityRole.IdentityRoleID.String(), data.IdentityRoleID.String())
	}
}

func (s *identityRoleBlackBoxTest) TestOKToLoad() {
	createAndLoadIdentityRole(s)
}

func (s *identityRoleBlackBoxTest) TestExistsRole() {
	t := s.T()

	t.Run("identity role exists", func(t *testing.T) {
		identityRole := createAndLoadIdentityRole(s)
		// when
		err := s.repo.CheckExists(s.Ctx, identityRole.IdentityRoleID.String())
		// then
		require.Nil(t, err)
	})

	t.Run("identity role doesn't exist", func(t *testing.T) {
		// Check not existing
		err := s.repo.CheckExists(s.Ctx, uuid.Must(uuid.NewV4()).String())
		// then
		require.IsType(t, errors.NotFoundError{}, err)
	})
}

func (s *identityRoleBlackBoxTest) TestFindPermissions() {
	// Create a new resource type
	resourceType, err := testsupport.CreateTestResourceType(s.Ctx, s.DB, "identity_role_test/test_resource_type")
	require.NoError(s.T(), err)

	// Create two scopes for the new resource type
	resourceTypeScopeFoo, err := testsupport.CreateTestScope(s.Ctx, s.DB, *resourceType, "test_scope_foo")
	require.NoError(s.T(), err)

	resourceTypeScopeBar, err := testsupport.CreateTestScope(s.Ctx, s.DB, *resourceType, "test_scope_bar")
	require.NoError(s.T(), err)

	// Create a new role
	role, err := testsupport.CreateTestRole(s.Ctx, s.DB, *resourceType, uuid.Must(uuid.NewV4()).String())
	require.NoError(s.T(), err)

	// Assign the two scopes to the role
	_, err = testsupport.CreateTestRoleScope(s.Ctx, s.DB, *resourceTypeScopeFoo, *role)
	require.NoError(s.T(), err)

	_, err = testsupport.CreateTestRoleScope(s.Ctx, s.DB, *resourceTypeScopeBar, *role)
	require.NoError(s.T(), err)

	// Create a test resource
	resource, err := testsupport.CreateTestResource(s.Ctx, s.DB, *resourceType, uuid.Must(uuid.NewV4()).String(), nil)
	require.NoError(s.T(), err)

	// Assign the new role for our new resource to a user
	identityRole, err := testsupport.CreateTestIdentityRole(s.Ctx, s.DB, *resource, *role)
	require.NoError(s.T(), err)

	// Search for permissions for the identity, resource and scope name
	identityRoles, err := s.repo.FindPermissions(s.Ctx, identityRole.IdentityID, identityRole.ResourceID, resourceTypeScopeFoo.Name)
	require.NoError(s.T(), err)

	require.Len(s.T(), identityRoles, 1)
	require.Equal(s.T(), identityRole.IdentityRoleID, identityRoles[0].IdentityRoleID)

	// Search for permissions for the identity, resource and second scope name
	identityRoles, err = s.repo.FindPermissions(s.Ctx, identityRole.IdentityID, identityRole.ResourceID, resourceTypeScopeBar.Name)
	require.NoError(s.T(), err)
	require.Len(s.T(), identityRoles, 1)

	// Search for permissions for the identity, resource and invalid scope name
	identityRoles, err = s.repo.FindPermissions(s.Ctx, identityRole.IdentityID, identityRole.ResourceID, "unknown")
	require.NoError(s.T(), err)
	require.Len(s.T(), identityRoles, 0)
}

func (s *identityRoleBlackBoxTest) TestFindIdentityRolesForIdentity() {
	identityRole := createAndLoadIdentityRole(s)
	createAndLoadIdentityRole(s)

	associations, err := s.repo.FindIdentityRolesForIdentity(s.Ctx, identityRole.IdentityID, nil)
	require.NoError(s.T(), err)

	require.Len(s.T(), associations, 1)
	require.Equal(s.T(), identityRole.ResourceID, associations[0].ResourceID)
	require.Len(s.T(), associations[0].Roles, 1)
	require.Equal(s.T(), identityRole.Role.Name, associations[0].Roles[0])
}

func (s *identityRoleBlackBoxTest) TestFindIdentityRolesByResourceAndRoleName() {
	identityRole := createAndLoadIdentityRole(s)

	// Create one random identity role
	createAndLoadIdentityRole(s)

	// Create another identity role with the same resource as the first one, but a different role
	roleName := uuid.Must(uuid.NewV4()).String()
	otherRole, err := testsupport.CreateTestRole(s.Ctx, s.DB, identityRole.Resource.ResourceType, roleName)
	require.NoError(s.T(), err)

	_, err = testsupport.CreateTestIdentityRole(s.Ctx, s.DB, identityRole.Resource, *otherRole)
	require.NoError(s.T(), err)

	identityRoles, err := s.repo.FindIdentityRolesByResourceAndRoleName(s.Ctx, identityRole.ResourceID, identityRole.Role.Name)
	require.NoError(s.T(), err)

	require.Len(s.T(), identityRoles, 1)
	require.Equal(s.T(), identityRole.IdentityRoleID, identityRoles[0].IdentityRoleID)
}

func (s *identityRoleBlackBoxTest) TestFindIdentityRolesByResource() {
	identityRole := createAndLoadIdentityRole(s)
	createAndLoadIdentityRole(s)

	identityRoles, err := s.repo.FindIdentityRolesByResource(s.Ctx, identityRole.ResourceID)
	require.NoError(s.T(), err)

	require.Len(s.T(), identityRoles, 1)
	require.Equal(s.T(), identityRole.IdentityRoleID, identityRoles[0].IdentityRoleID)
}

func createAndLoadIdentityRole(s *identityRoleBlackBoxTest) *role.IdentityRole {
	ir, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(s.T(), err)
	return ir
}
