package repository_test

import (
	"context"
	"fmt"
	"testing"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/authorization"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	errs "github.com/pkg/errors"

	"github.com/fabric8-services/fabric8-auth/authorization/token"
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

func TestIdentityRoleBlackBoxTest(t *testing.T) {
	suite.Run(t, &identityRoleBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *identityRoleBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
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
	// Test space
	space := s.Graph.CreateSpace()
	// One viewer in the space
	space.AddViewer(s.Graph.CreateUser())
	// And 5 admins&contributors
	for i := 0; i < 5; i++ {
		u := s.Graph.CreateUser()
		space.AddAdmin(u)
		space.AddContributor(u)
	}

	// Another space which we won't delete
	spaceX := s.Graph.CreateSpace()
	for i := 0; i < 5; i++ {
		spaceX.AddAdmin(s.Graph.CreateUser())
	}

	// Check all expected identity roles are present
	idRoles, err := s.repo.FindIdentityRolesByResource(s.Ctx, space.SpaceID(), false)
	require.NoError(s.T(), err)
	assert.Len(s.T(), idRoles, 11)

	// Delete identity role for the space
	err = s.repo.DeleteForResource(s.Ctx, space.SpaceID())
	require.NoError(s.T(), err)

	// Check the identity roles for the space are gone
	idRoles, err = s.repo.FindIdentityRolesByResource(s.Ctx, space.SpaceID(), false)
	require.NoError(s.T(), err)
	assert.Len(s.T(), idRoles, 0)

	// Delete action on the resource with no identity roles should not fail
	err = s.repo.DeleteForResource(s.Ctx, space.SpaceID())
	require.NoError(s.T(), err)

	// Check the identity roles for the other space are still preset
	idRoles, err = s.repo.FindIdentityRolesByResource(s.Ctx, spaceX.SpaceID(), false)
	require.NoError(s.T(), err)
	assert.Len(s.T(), idRoles, 5)
}

func (s *identityRoleBlackBoxTest) TestDeleteForIdentityAndResourceOK() {
	// Test space
	space := s.Graph.CreateSpace()
	// One viewer/contributor in the space to stay
	userToStay := s.Graph.CreateUser()
	space.AddViewer(userToStay).AddContributor(userToStay)

	// One viewer/contributor in the space which roles we want to delete
	userToDelete := s.Graph.CreateUser()
	space.AddViewer(userToDelete).AddContributor(userToDelete)

	// Make some noise
	spaceX := s.Graph.CreateSpace()
	for i := 0; i < 5; i++ {
		spaceX.AddAdmin(s.Graph.CreateUser()).AddContributor(s.Graph.CreateUser())
	}

	// Check all expected identity roles are present
	idRoles, err := s.repo.FindIdentityRolesByResource(s.Ctx, space.SpaceID(), false)
	require.NoError(s.T(), err)
	assert.Len(s.T(), idRoles, 4)

	// Delete identity role for the space and user
	err = s.repo.DeleteForIdentityAndResource(s.Ctx, space.SpaceID(), userToDelete.Identity().ID)
	require.NoError(s.T(), err)

	// Check the identity roles for the space and user are gone
	idRoles, err = s.repo.FindIdentityRolesByIdentityAndResource(s.Ctx, space.SpaceID(), userToDelete.Identity().ID)
	require.NoError(s.T(), err)
	assert.Len(s.T(), idRoles, 0)

	// Delete action should fail if no identity roles found
	err = s.repo.DeleteForIdentityAndResource(s.Ctx, space.SpaceID(), userToDelete.Identity().ID)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "identity_role with resource_id '%s' and identity_id '%s' not found", space.SpaceID(), userToDelete.Identity().ID)

	// Check the identity roles for the other user for this space are still preset
	idRoles, err = s.repo.FindIdentityRolesByIdentityAndResource(s.Ctx, space.SpaceID(), userToStay.Identity().ID)
	require.NoError(s.T(), err)
	assert.Len(s.T(), idRoles, 2)

	// Check the identity roles for the other space are still preset
	idRoles, err = s.repo.FindIdentityRolesByResource(s.Ctx, spaceX.SpaceID(), false)
	require.NoError(s.T(), err)
	assert.Len(s.T(), idRoles, 10)
}

func (s *identityRoleBlackBoxTest) TestOKToDeleteForUnknownResource() {
	err := s.repo.DeleteForResource(s.Ctx, uuid.NewV4().String())
	require.NoError(s.T(), err)
}

func (s *identityRoleBlackBoxTest) TestDeleteForUnknownIdentityAndResourceFails() {
	space := s.Graph.CreateSpace()
	//space.AddViewer(g.CreateUser())

	// Unknown user
	unknownIdentityID := uuid.NewV4()
	err := s.repo.DeleteForIdentityAndResource(s.Ctx, space.SpaceID(), unknownIdentityID)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "identity_role with resource_id '%s' and identity_id '%s' not found", space.SpaceID(), unknownIdentityID)

	// Unknown resource
	unknownResourceID := uuid.NewV4().String()
	identityID := s.Graph.CreateUser().Identity().ID
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
	orgAdmin := s.Graph.CreateUser()
	org := s.Graph.CreateOrganization(orgAdmin)

	spaceViewer := s.Graph.CreateUser()
	spaceContributor := s.Graph.CreateUser()
	spaceAdmin := s.Graph.CreateUser()
	space := s.Graph.CreateSpace(org).AddViewer(spaceViewer).AddContributor(spaceContributor).AddAdmin(spaceAdmin)

	childResource := s.Graph.CreateResource(space)

	// noise
	s.Graph.CreateSpace().AddAdmin(s.Graph.CreateUser())

	// Without parent resources
	identityRoles, err := s.repo.FindIdentityRolesByResourceAndRoleName(s.Ctx, childResource.ResourceID(), "admin", false)
	require.NoError(s.T(), err)
	require.Len(s.T(), identityRoles, 0)

	identityRoles, err = s.repo.FindIdentityRolesByResourceAndRoleName(s.Ctx, space.SpaceID(), "viewer", false)
	require.NoError(s.T(), err)
	require.Len(s.T(), identityRoles, 1)
	validateAssignee(s.T(), []uuid.UUID{spaceViewer.IdentityID()}, space.SpaceID(), identityRoles)

	// With parent resources
	identityRoles, err = s.repo.FindIdentityRolesByResourceAndRoleName(s.Ctx, childResource.ResourceID(), "admin", true)
	require.NoError(s.T(), err)
	require.Len(s.T(), identityRoles, 2)
	validateAssignee(s.T(), []uuid.UUID{orgAdmin.IdentityID()}, org.ResourceID(), identityRoles)
	validateAssignee(s.T(), []uuid.UUID{spaceAdmin.IdentityID()}, space.SpaceID(), identityRoles)
}

func (s *identityRoleBlackBoxTest) TestFindIdentityRolesByResourceAndRoleNameOrder() {
	org := s.Graph.CreateOrganization(s.Graph.CreateUser())
	space := s.Graph.CreateSpace(org)
	for i := 0; i < 10; i++ {
		space.AddViewer(s.Graph.CreateUser()).AddContributor(s.Graph.CreateUser()).AddAdmin(s.Graph.CreateUser())
	}
	childResource := s.Graph.CreateResource(space)

	// Without parent resources
	identityRoles, err := s.repo.FindIdentityRolesByResourceAndRoleName(s.Ctx, space.SpaceID(), "viewer", false)
	require.NoError(s.T(), err)
	require.Len(s.T(), identityRoles, 10)

	for i := 0; i < 10; i++ {
		ir, err := s.repo.FindIdentityRolesByResourceAndRoleName(s.Ctx, space.SpaceID(), "viewer", false)
		require.NoError(s.T(), err)
		require.Equal(s.T(), identityRoles, ir) // Order should be the same every time
	}

	// With parent resources
	identityRoles, err = s.repo.FindIdentityRolesByResourceAndRoleName(s.Ctx, childResource.ResourceID(), "admin", true)
	require.NoError(s.T(), err)
	require.Len(s.T(), identityRoles, 11)
	for i := 0; i < 10; i++ {
		ir, err := s.repo.FindIdentityRolesByResourceAndRoleName(s.Ctx, space.SpaceID(), "admin", true)
		require.NoError(s.T(), err)
		require.Equal(s.T(), identityRoles, ir) // Order should be the same every time
	}
}

func (s *identityRoleBlackBoxTest) TestFindIdentityRolesByResourceOrder() {
	org := s.Graph.CreateOrganization(s.Graph.CreateUser())
	space := s.Graph.CreateSpace(org)
	for i := 0; i < 10; i++ {
		space.AddViewer(s.Graph.CreateUser()).AddContributor(s.Graph.CreateUser()).AddAdmin(s.Graph.CreateUser())
	}
	childResource := s.Graph.CreateResource(space)

	// Without parent resources
	identityRoles, err := s.repo.FindIdentityRolesByResource(s.Ctx, space.SpaceID(), false)
	require.NoError(s.T(), err)
	require.Len(s.T(), identityRoles, 30)
	for i := 0; i < 10; i++ {
		ir, err := s.repo.FindIdentityRolesByResource(s.Ctx, space.SpaceID(), false)
		require.NoError(s.T(), err)
		require.Equal(s.T(), identityRoles, ir) // Order should be the same every time
	}

	// With parent resources
	identityRoles, err = s.repo.FindIdentityRolesByResource(s.Ctx, childResource.ResourceID(), true)
	require.NoError(s.T(), err)
	require.Len(s.T(), identityRoles, 31)
	for i := 0; i < 10; i++ {
		ir, err := s.repo.FindIdentityRolesByResource(s.Ctx, space.SpaceID(), true)
		require.NoError(s.T(), err)
		require.Equal(s.T(), identityRoles, ir) // Order should be the same every time
	}
}

func (s *identityRoleBlackBoxTest) TestFindIdentityRolesByResource() {
	orgAdmin := s.Graph.CreateUser()
	org := s.Graph.CreateOrganization(orgAdmin)

	spaceViewer := s.Graph.CreateUser()
	spaceContributor := s.Graph.CreateUser()
	space := s.Graph.CreateSpace(org).AddViewer(spaceViewer).AddContributor(spaceContributor)

	childResource := s.Graph.CreateResource(space)

	// noise
	s.Graph.CreateSpace().AddAdmin(s.Graph.CreateUser())

	// Without parent resources
	identityRoles, err := s.repo.FindIdentityRolesByResource(s.Ctx, childResource.ResourceID(), false)
	require.NoError(s.T(), err)
	require.Len(s.T(), identityRoles, 0)

	identityRoles, err = s.repo.FindIdentityRolesByResource(s.Ctx, space.SpaceID(), false)
	require.NoError(s.T(), err)
	require.Len(s.T(), identityRoles, 2)
	validateAssignee(s.T(), []uuid.UUID{spaceViewer.IdentityID(), spaceContributor.IdentityID()}, space.SpaceID(), identityRoles)

	// With parent resources
	identityRoles, err = s.repo.FindIdentityRolesByResource(s.Ctx, childResource.ResourceID(), true)
	require.NoError(s.T(), err)
	require.Len(s.T(), identityRoles, 3)
	validateAssignee(s.T(), []uuid.UUID{spaceViewer.IdentityID(), spaceContributor.IdentityID()}, space.SpaceID(), identityRoles)
	validateAssignee(s.T(), []uuid.UUID{orgAdmin.IdentityID()}, org.ResourceID(), identityRoles)
}

func (s *identityRoleBlackBoxTest) TestFindIdentityRolesByIdentityAndResource() {
	newSpace := s.Graph.CreateSpace()

	var createdIdentities []uuid.UUID

	for i := 0; i <= 10; i++ {
		user := s.Graph.CreateUser()
		newSpace.AddAdmin(user)
		createdIdentities = append(createdIdentities, user.Identity().ID)
	}

	// noise
	for i := 0; i <= 10; i++ {
		s.Graph.CreateSpace().AddAdmin(s.Graph.CreateUser())
		newSpace.AddContributor(s.Graph.CreateUser())
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
	newSpace := s.Graph.CreateSpace()

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
	newSpace := s.Graph.CreateSpace()
	existingUser := s.Graph.CreateUser()

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
	existingUser := s.Graph.CreateUser()
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
	existingUser := s.Graph.CreateUser()
	knownRoleID := getKnownRoleIDForSpace(s)
	newSpace := s.Graph.CreateSpace()

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

func validateAssignee(t *testing.T, amongUsers []uuid.UUID, resourceID string, returnedAssignedRoles []role.IdentityRole) {
	for _, returnedAssignment := range returnedAssignedRoles {
		assert.NotEmpty(t, returnedAssignment.Resource)
		assert.NotEmpty(t, returnedAssignment.Identity)
		assert.NotEmpty(t, returnedAssignment.Role)
		for _, i := range amongUsers {
			if i == returnedAssignment.IdentityID {
				assert.Equal(t, resourceID, returnedAssignment.ResourceID)
				return
			}
		}
	}
	assert.Fail(t, "user not found")
}

func (s *identityRoleBlackBoxTest) TestFindScopesByIdentityAndResource() {
	// Create a new resource type to use for the duration of the test, with two scopes; foo and bar
	rt := s.Graph.CreateResourceType()
	rt.AddScope("foo")
	rt.AddScope("bar")

	// Create a foo role with the foo scope
	fooRole := s.Graph.CreateRole(rt)
	fooRole.AddScope("foo")

	// Create a bar role with the bar scope
	barRole := s.Graph.CreateRole(rt)
	barRole.AddScope("bar")

	// Create a foobar role with both foo and bar scopes
	fooBarRole := s.Graph.CreateRole(rt)
	fooBarRole.AddScope("foo").AddScope("bar")

	// Create a user
	user1 := s.Graph.CreateUser()

	// Create a resource with the new resource type
	resource1 := s.Graph.CreateResource(rt)

	// Assign a role directly to the user
	s.Graph.CreateIdentityRole(user1, resource1, fooRole)

	// Lookup all of user's scopes for the resource
	scopes, err := s.repo.FindScopesByIdentityAndResource(s.Ctx, user1.IdentityID(), resource1.ResourceID())
	require.NoError(s.T(), err)

	// There should be one scope, "foo"
	require.ElementsMatch(s.T(), scopes, []string{"foo"})

	// Create a child resource of the first resource, of the same resource type
	childResource := s.Graph.CreateResource(rt, resource1)

	// It should inherit the privileges from its parent resource
	scopes, err = s.repo.FindScopesByIdentityAndResource(s.Ctx, user1.IdentityID(), childResource.ResourceID())
	require.NoError(s.T(), err)
	require.ElementsMatch(s.T(), scopes, []string{"foo"})

	// Create a great-grandchild resource of the first resource
	ggcResource := s.Graph.CreateResource(rt, s.Graph.CreateResource(rt, childResource))

	// It shouldn't matter how deep the hierarchy is, resources always inherit privileges their parent resource of the same type
	scopes, err = s.repo.FindScopesByIdentityAndResource(s.Ctx, user1.IdentityID(), ggcResource.ResourceID())
	require.NoError(s.T(), err)
	require.ElementsMatch(s.T(), scopes, []string{"foo"})

	// Confirm that the user doesn't have any scopes for a random other resource of the same resource type
	otherResource := s.Graph.CreateResource(rt)
	scopes, err = s.repo.FindScopesByIdentityAndResource(s.Ctx, user1.IdentityID(), otherResource.ResourceID())
	require.NoError(s.T(), err)
	require.Empty(s.T(), scopes)

	// create another user
	user2 := s.Graph.CreateUser()
	// Create a resource with the new resource type
	resource2 := s.Graph.CreateResource(rt)
	// Assign roles directly to the user
	s.Graph.CreateIdentityRole(user2, resource2, fooRole)
	s.Graph.CreateIdentityRole(user2, resource2, fooBarRole)
	scopes, err = s.repo.FindScopesByIdentityAndResource(s.Ctx, user2.IdentityID(), resource2.ResourceID())
	require.NoError(s.T(), err)
	require.ElementsMatch(s.T(), scopes, []string{"foo", "bar"}) // no scope duplicates

	// Create another user
	user3 := s.Graph.CreateUser()
	// Create a team and add the user to the team
	team := s.Graph.CreateTeam()
	team.AddMember(user3)

	// Create a resource with the new resource type
	resource3 := s.Graph.CreateResource(rt)

	// Assign a role directly to the team
	s.Graph.CreateIdentityRole(team, resource3, barRole)

	// Lookup all of user3's scopes for the resource
	scopes, err = s.repo.FindScopesByIdentityAndResource(s.Ctx, user3.IdentityID(), resource3.ResourceID())
	require.NoError(s.T(), err)

	// There should be one scope, "bar"
	require.ElementsMatch(s.T(), scopes, []string{"bar"})

	// Now lookup all of user's scopes for resource3
	scopes, err = s.repo.FindScopesByIdentityAndResource(s.Ctx, user1.IdentityID(), resource3.ResourceID())
	require.NoError(s.T(), err)

	// There should be no scopes
	require.Empty(s.T(), scopes)

	// Create another user
	user4 := s.Graph.CreateUser()
	// Create a team and add the user to the team
	team4 := s.Graph.CreateTeam()
	team4.AddMember(user4)
	// Create an organization and add the team to the org
	org3 := s.Graph.CreateOrganization()
	org3.AddMember(team4)

	// Create a resource with the new resource type
	resource4 := s.Graph.CreateResource(rt)

	// Assign a role directly to the org
	s.Graph.CreateIdentityRole(org3, resource4, fooBarRole)

	// Lookup all of user4's scopes for the resource
	scopes, err = s.repo.FindScopesByIdentityAndResource(s.Ctx, user4.IdentityID(), resource4.ResourceID())
	require.NoError(s.T(), err)

	// There should be two scopes, "foo" and "bar"
	require.ElementsMatch(s.T(), scopes, []string{"foo", "bar"})

	// Create another resource type, with scope "alpha"
	rt2 := s.Graph.CreateResourceType()
	rt2.AddScope("alpha")

	// Create an role with the alpha scope
	alphaRole := s.Graph.CreateRole(rt2)
	alphaRole.AddScope("alpha")

	// Create a child resource of resource4, but with the new resource type
	resource4Child := s.Graph.CreateResource(rt2, resource4)

	// user4 should not have any scopes for the new child resource
	scopes, err = s.repo.FindScopesByIdentityAndResource(s.Ctx, user4.IdentityID(), resource4Child.ResourceID())
	require.NoError(s.T(), err)
	require.Empty(s.T(), scopes)

	// Map the fooBar role to the alphaRole for resource4
	s.Graph.CreateRoleMapping(resource4, fooBarRole, alphaRole)

	// Now user4 should have the alpha scope for the new child resource, as the fooBar role is mapped to the alpha role
	scopes, err = s.repo.FindScopesByIdentityAndResource(s.Ctx, user4.IdentityID(), resource4Child.ResourceID())
	require.NoError(s.T(), err)
	require.ElementsMatch(s.T(), scopes, []string{"alpha"})

	// Create yet another resource type, with scope "bravo"
	rt3 := s.Graph.CreateResourceType()
	rt3.AddScope("bravo")

	// Create a role with the bravo scope
	bravoRole := s.Graph.CreateRole(rt3)
	bravoRole.AddScope("bravo")

	// Create a grandchild resource of resource4, with the new resource type
	resource4Grandchild := s.Graph.CreateResource(rt3, resource4Child)

	// user4 should not have any scopes for the new grandchild resource
	scopes, err = s.repo.FindScopesByIdentityAndResource(s.Ctx, user4.IdentityID(), resource4Grandchild.ResourceID())
	require.NoError(s.T(), err)
	require.Empty(s.T(), scopes)

	// Map alphaRole to bravoRole for the resource
	s.Graph.CreateRoleMapping(resource4, alphaRole, bravoRole)

	// Ensure that privileges correctly traverse the role mapping hierarchy for a resource
	scopes, err = s.repo.FindScopesByIdentityAndResource(s.Ctx, user4.IdentityID(), resource4Grandchild.ResourceID())
	require.NoError(s.T(), err)
	require.ElementsMatch(s.T(), scopes, []string{"bravo"})
}

func (s *identityRoleBlackBoxTest) TestFlagPrivilegeCacheAsStale() {
	// Create a couple of new privilege cache records
	pc := s.Graph.CreatePrivilegeCache("foo", "bar")
	pc2 := s.Graph.CreatePrivilegeCache("foo", "bar")

	// Create a couple of token records
	t := s.Graph.CreateToken()
	t2 := s.Graph.CreateToken()

	// Link token t to privilege cache entry pc
	t.AddPrivilege(pc)

	// Assert that the privilege caches are not stale
	require.False(s.T(), pc.PrivilegeCache().Stale)
	require.False(s.T(), pc2.PrivilegeCache().Stale)

	// Assert that the tokens are not stale
	require.False(s.T(), t.Token().HasStatus(token.TOKEN_STATUS_STALE))
	require.False(s.T(), t2.Token().HasStatus(token.TOKEN_STATUS_STALE))

	// Flag the privilege cache as stale
	err := s.repo.FlagPrivilegeCacheStaleForIdentityRoleChange(s.Ctx, pc.PrivilegeCache().IdentityID, pc.PrivilegeCache().ResourceID)
	require.NoError(s.T(), err)

	// Reload the privilege cache
	pc = s.Graph.LoadPrivilegeCache(pc.PrivilegeCache().PrivilegeCacheID)

	// Assert that the cache is now stale
	require.True(s.T(), pc.PrivilegeCache().Stale)

	// Assert that pc2 is still not stale
	pc2 = s.Graph.LoadPrivilegeCache(pc2.PrivilegeCache().PrivilegeCacheID)
	require.False(s.T(), pc2.PrivilegeCache().Stale)

	// Reload the token
	t = s.Graph.LoadToken(s.Ctx, t.TokenID())

	// Assert that the token is now stale
	require.True(s.T(), t.Token().HasStatus(token.TOKEN_STATUS_STALE))

	// Assert that t2 is still not stale
	t2 = s.Graph.LoadToken(s.Ctx, t2.TokenID())
	require.False(s.T(), t2.Token().HasStatus(token.TOKEN_STATUS_STALE))
}
