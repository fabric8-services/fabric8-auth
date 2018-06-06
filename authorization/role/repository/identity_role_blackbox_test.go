package repository_test

import (
	"github.com/fabric8-services/fabric8-auth/authorization"
	"testing"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	errs "github.com/pkg/errors"

	"context"
	"fmt"
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

func (s *identityRoleBlackBoxTest) TestDeleteUnknownFails() {
	identityRoleID := uuid.NewV4()

	err := s.repo.Delete(s.Ctx, identityRoleID)
	require.Error(s.T(), err)
	assert.Equal(s.T(), fmt.Sprintf("identity_role with id '%s' not found", identityRoleID), err.Error())
}

func (s *identityRoleBlackBoxTest) TestOKToDeleteForResource() {
	g := s.NewTestGraph()

	// Test space
	space := g.CreateSpace()
	// One viewer in the space
	space.AddViewer(g.CreateUser())
	// And 5 admins&contributors
	for i := 0; i < 5; i++ {
		u := g.CreateUser()
		space.AddAdmin(u)
		space.AddContributor(u)
	}

	// Another space which we won't delete
	spaceX := g.CreateSpace()
	for i := 0; i < 5; i++ {
		spaceX.AddAdmin(g.CreateUser())
	}

	// Check all expected identity roles are present
	idRoles, err := s.repo.FindIdentityRolesByResource(s.Ctx, space.SpaceID())
	require.NoError(s.T(), err)
	assert.Len(s.T(), idRoles, 11)

	// Delete identity role for the space
	err = s.repo.DeleteForResource(s.Ctx, space.SpaceID())
	require.NoError(s.T(), err)

	// Check the identity roles for the space are gone
	idRoles, err = s.repo.FindIdentityRolesByResource(s.Ctx, space.SpaceID())
	require.NoError(s.T(), err)
	assert.Len(s.T(), idRoles, 0)

	// Delete action on the resource with no identity roles should not fail
	err = s.repo.DeleteForResource(s.Ctx, space.SpaceID())
	require.NoError(s.T(), err)

	// Check the identity roles for the other space are still preset
	idRoles, err = s.repo.FindIdentityRolesByResource(s.Ctx, spaceX.SpaceID())
	require.NoError(s.T(), err)
	assert.Len(s.T(), idRoles, 5)
}

func (s *identityRoleBlackBoxTest) TestOKToDeleteForUnknownResource() {
	err := s.repo.DeleteForResource(s.Ctx, uuid.NewV4().String())
	require.NoError(s.T(), err)
}

func (s *identityRoleBlackBoxTest) TestDeleteForUnknownIdentityAndResourceFails() {
	g := s.NewTestGraph()
	space := g.CreateSpace()
	//space.AddViewer(g.CreateUser())

	// Unknown user
	unknownIdentityID := uuid.NewV4()
	err := s.repo.DeleteForIdentityAndResource(s.Ctx, space.SpaceID(), unknownIdentityID)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "identity_role with resource_id '%s' and identity_id '%s' not found", space.SpaceID(), unknownIdentityID)

	// Unknown resource
	unknownResourceID := uuid.NewV4().String()
	identityID := g.CreateUser().Identity().ID
	err = s.repo.DeleteForIdentityAndResource(s.Ctx, unknownResourceID, identityID)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "identity_role with resource_id '%s' and identity_id '%s' not found", unknownResourceID, identityID)

	// Resource with no identity roles
	err = s.repo.DeleteForIdentityAndResource(s.Ctx, space.SpaceID(), identityID)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "identity_role with resource_id '%s' and identity_id '%s' not found", space.SpaceID(), identityID)
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
		err := s.repo.CheckExists(s.Ctx, uuid.NewV4().String())
		// then
		require.IsType(t, errors.NotFoundError{}, err)
	})
}

func (s *identityRoleBlackBoxTest) TestExistsUnknownIdentityRoleFails() {
	id := uuid.NewV4().String()
	err := s.repo.CheckExists(s.Ctx, id)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "identity_role with id '%s' not found", id)
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
	role, err := testsupport.CreateTestRole(s.Ctx, s.DB, *resourceType, uuid.NewV4().String())
	require.NoError(s.T(), err)

	// Assign the two scopes to the role
	_, err = testsupport.CreateTestRoleScope(s.Ctx, s.DB, *resourceTypeScopeFoo, *role)
	require.NoError(s.T(), err)

	_, err = testsupport.CreateTestRoleScope(s.Ctx, s.DB, *resourceTypeScopeBar, *role)
	require.NoError(s.T(), err)

	// Create a test resource
	resource, err := testsupport.CreateTestResource(s.Ctx, s.DB, *resourceType, uuid.NewV4().String(), nil)
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
	roleName := uuid.NewV4().String()
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

func (s *identityRoleBlackBoxTest) TestFindIdentityRolesByIdentityAndResource() {
	g := s.DBTestSuite.NewTestGraph()
	newSpace := g.CreateSpace()

	var createdIdentities []uuid.UUID

	for i := 0; i <= 10; i++ {
		user := g.CreateUser()
		newSpace.AddAdmin(user)
		createdIdentities = append(createdIdentities, user.Identity().ID)
	}

	// noise
	for i := 0; i <= 10; i++ {
		g.CreateSpace().AddAdmin(g.CreateUser())
		newSpace.AddContributor(g.CreateUser())
	}

	for _, i := range createdIdentities {
		result, err := s.repo.FindIdentityRolesByIdentityAndResource(context.Background(), newSpace.SpaceID(), i)
		require.NoError(s.T(), err)
		require.Len(s.T(), result, 1)
		require.Equal(s.T(), i, result[0].IdentityID)
		require.Equal(s.T(), newSpace.SpaceID(), result[0].ResourceID)
	}
}

func (s *identityRoleBlackBoxTest) TestCreateIdentityRolesUnknownIdentity() {
	g := s.DBTestSuite.NewTestGraph()
	newSpace := g.CreateSpace()

	knownRoleID := getKnownRoleIDForSpace(s)

	ir := role.IdentityRole{
		IdentityRoleID: uuid.NewV4(),
		IdentityID:     uuid.NewV4(), // unknown identity
		ResourceID:     newSpace.SpaceID(),
		RoleID:         knownRoleID,
	}
	err := s.repo.Create(context.Background(), &ir)
	require.IsType(s.T(), errors.NotFoundError{}, errs.Cause(err))
}

func (s *identityRoleBlackBoxTest) TestCreateIdentityRolesUnknownRole() {
	g := s.DBTestSuite.NewTestGraph()
	newSpace := g.CreateSpace()
	existingUser := g.CreateUser()

	ir := role.IdentityRole{
		IdentityRoleID: uuid.NewV4(),
		IdentityID:     existingUser.Identity().ID,
		ResourceID:     newSpace.SpaceID(),
		RoleID:         uuid.NewV4(), // unknown role
	}
	err := s.repo.Create(context.Background(), &ir)
	require.IsType(s.T(), errors.NotFoundError{}, errs.Cause(err))
}

func (s *identityRoleBlackBoxTest) TestCreateIdentityRolesUnknownResource() {
	g := s.DBTestSuite.NewTestGraph()

	existingUser := g.CreateUser()
	knownRoleID := getKnownRoleIDForSpace(s)

	ir := role.IdentityRole{
		IdentityRoleID: uuid.NewV4(),
		IdentityID:     existingUser.Identity().ID,
		ResourceID:     uuid.NewV4().String(),
		RoleID:         knownRoleID,
	}
	err := s.repo.Create(context.Background(), &ir)
	require.IsType(s.T(), errors.NotFoundError{}, errs.Cause(err))
}

func (s *identityRoleBlackBoxTest) TestCreateIdentityExistingAssignmentFails() {
	g := s.DBTestSuite.NewTestGraph()

	existingUser := g.CreateUser()
	knownRoleID := getKnownRoleIDForSpace(s)
	newSpace := g.CreateSpace()

	ir := role.IdentityRole{
		IdentityRoleID: uuid.NewV4(),
		IdentityID:     existingUser.Identity().ID,
		ResourceID:     newSpace.SpaceID(),
		RoleID:         knownRoleID,
	}
	err := s.repo.Create(context.Background(), &ir)
	require.NoError(s.T(), err)

	ir.IdentityRoleID = uuid.NewV4()
	err = s.repo.Create(context.Background(), &ir)
	require.IsType(s.T(), errors.DataConflictError{}, errs.Cause(err))
}

func getKnownRoleIDForSpace(s *identityRoleBlackBoxTest) uuid.UUID {
	roles, err := s.roleRepo.FindRolesByResourceType(context.Background(), authorization.ResourceTypeSpace)
	require.Nil(s.T(), err)
	require.Len(s.T(), roles, 3)

	knownRoleID, err := uuid.FromString(roles[0].RoleID)
	require.Nil(s.T(), err)
	return knownRoleID
}

func createAndLoadIdentityRole(s *identityRoleBlackBoxTest) *role.IdentityRole {
	ir, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(s.T(), err)
	return ir
}
