package service_test

import (
	"context"
	"testing"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/authorization"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type roleManagementServiceBlackboxTest struct {
	gormtestsupport.DBTestSuite
	service           service.RoleManagementService
	roleRepo          rolerepo.RoleRepository
	resourceTypeScope resourcetype.ResourceTypeScopeRepository
}

func TestRunRoleManagementServiceBlackboxTest(t *testing.T) {
	suite.Run(t, &roleManagementServiceBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *roleManagementServiceBlackboxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.service = s.Application.RoleManagementService()
	s.roleRepo = rolerepo.NewRoleRepository(s.DB)
	s.resourceTypeScope = resourcetype.NewResourceTypeScopeRepository(s.DB)
}

func (s *roleManagementServiceBlackboxTest) TestGetIdentityRoleByResource() {
	t := s.T()
	admin := s.Graph.CreateUser()
	viewer := s.Graph.CreateUser()
	space := s.Graph.CreateSpace().AddAdmin(admin).AddViewer(viewer)

	// noise
	s.Graph.CreateSpace().AddViewer(s.Graph.CreateUser())

	// User should have view scope to list roles
	idnt := s.Graph.CreateUser().IdentityID()
	_, err := s.service.ListByResource(s.Ctx, idnt, space.SpaceID())
	testsupport.AssertError(s.T(), err, errors.ForbiddenError{}, "identity with ID %s does not have required scope view for resource %s", idnt.String(), space.SpaceID())

	// Check available roles
	identityRoles, err := s.service.ListByResource(s.Ctx, viewer.IdentityID(), space.SpaceID())
	require.NoError(t, err)
	require.Len(t, identityRoles, 2)
	validateAssignee(t, []uuid.UUID{admin.IdentityID(), viewer.IdentityID()}, space.SpaceID(), identityRoles)

	// Fail if resource is unknown
	id := uuid.NewV4().String()
	_, err = s.service.ListByResource(s.Ctx, viewer.IdentityID(), id)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "resource with id '%s' not found", id)
}

func (s *roleManagementServiceBlackboxTest) TestGetIdentityRoleByResourceAndRoleName() {
	t := s.T()

	admin := s.Graph.CreateUser()
	viewer := s.Graph.CreateUser()
	space := s.Graph.CreateSpace().AddAdmin(admin).AddViewer(viewer)

	// noise
	s.Graph.CreateSpace().AddAdmin(s.Graph.CreateUser())

	// User should have view scope to list roles
	idnt := s.Graph.CreateUser().IdentityID()
	_, err := s.service.ListByResourceAndRoleName(s.Ctx, idnt, space.SpaceID(), authorization.ManageRoleAssignmentsInSpaceScope)
	testsupport.AssertError(s.T(), err, errors.ForbiddenError{}, "identity with ID %s does not have required scope view for resource %s", idnt.String(), space.SpaceID())

	// Check available roles
	identityRoles, err := s.service.ListByResourceAndRoleName(s.Ctx, viewer.IdentityID(), space.SpaceID(), authorization.SpaceAdminRole)
	require.NoError(t, err)
	require.Len(t, identityRoles, 1)
	assert.Equal(t, authorization.SpaceAdminRole, identityRoles[0].Role.Name)
	validateAssignee(t, []uuid.UUID{admin.IdentityID()}, space.SpaceID(), identityRoles)

	// Fail if resource is unknown
	id := uuid.NewV4().String()
	identityRoles, err = s.service.ListByResourceAndRoleName(s.Ctx, viewer.IdentityID(), id, authorization.ManageRoleAssignmentsInSpaceScope)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "resource with id '%s' not found", id)
}

func (s *roleManagementServiceBlackboxTest) TestGetRolesByResourceTypeOK() {

	var createdRoleScopes []rolerepo.RoleScope

	resourceType, err := testsupport.CreateTestResourceType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)

	role, err := testsupport.CreateTestRoleWithSpecifiedType(s.Ctx, s.DB, uuid.NewV4().String(), resourceType.Name)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), role)

	scope, err := testsupport.CreateTestScope(s.Ctx, s.DB, *resourceType, uuid.NewV4().String())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), scope)

	rs, err := testsupport.CreateTestRoleScope(s.Ctx, s.DB, *scope, *role)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rs)

	createdRoleScopes = append(createdRoleScopes, *rs)

	roleScopesRetrieved, err := s.service.ListAvailableRolesByResourceType(s.Ctx, resourceType.Name)
	require.NoError(s.T(), err)

	// there might be other 'RoleScopes' returned too.
	// That wouldn't be considered to be a failure, rather we are gonna check whether they all
	// belong to the same resource type.
	s.checkRoleBelongsToResourceType(s.DB, roleScopesRetrieved, *resourceType)

	// Then let's check if the ones we created are there.
	s.checkIfCreatedRoleScopesAreReturned(s.DB, roleScopesRetrieved, createdRoleScopes)
}

func (s *roleManagementServiceBlackboxTest) TestGetRolesByResourceTypeOKEmpty() {

	// create entities in the existing resource type
	role, err := testsupport.CreateTestRoleWithDefaultType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), role)

	scope, err := testsupport.CreateTestScopeWithDefaultType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), scope)

	rs, err := testsupport.CreateTestRoleScope(s.Ctx, s.DB, *scope, *role)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rs)

	// create another resource type
	newResourceTypeName := uuid.NewV4().String()
	_, err = testsupport.CreateTestResourceType(s.Ctx, s.DB, newResourceTypeName)
	require.NoError(s.T(), err)

	roleScopesRetrieved, err := s.service.ListAvailableRolesByResourceType(s.Ctx, newResourceTypeName)
	require.NoError(s.T(), err)
	require.Len(s.T(), roleScopesRetrieved, 0)
}

func (s *roleManagementServiceBlackboxTest) checkIfCreatedRoleScopesAreReturned(db *gorm.DB, roleScopesRetrieved []role.RoleDescriptor, createdRoleScopes []rolerepo.RoleScope) {
	foundCreatedRoleScope := false
	for _, rsDB := range createdRoleScopes {
		foundCreatedRoleScope = false
		for _, rsRetrieved := range roleScopesRetrieved {
			if rsDB.RoleID.String() == rsRetrieved.RoleID {
				for _, sc := range rsRetrieved.Scopes {
					if sc == rsDB.ResourceTypeScope.Name {
						foundCreatedRoleScope = true
					}
				}
			}
		}
		require.True(s.T(), foundCreatedRoleScope)
	}
}

func (s *roleManagementServiceBlackboxTest) checkRoleBelongsToResourceType(db *gorm.DB, roleScopesRetrieved []role.RoleDescriptor, rt resourcetype.ResourceType) {
	require.True(s.T(), len(roleScopesRetrieved) >= 1)
	for _, r := range roleScopesRetrieved {
		roleID, err := uuid.FromString(r.RoleID)
		require.NoError(s.T(), err)

		existingRole, err := s.roleRepo.Load(s.Ctx, roleID)
		require.NoError(s.T(), err)
		require.NotNil(s.T(), existingRole)

		// this role should belong to the specific resource type
		require.Equal(s.T(), rt.ResourceTypeID, existingRole.ResourceTypeID)
		for _, sc := range r.Scopes {
			s.checkScopeBelongsToResourceType(s.DB, sc, rt)
		}
	}
}

func (s *roleManagementServiceBlackboxTest) checkScopeBelongsToResourceType(db *gorm.DB, scopeName string, rt resourcetype.ResourceType) {
	scopesReturned, err := s.resourceTypeScope.LookupByResourceTypeAndScope(s.Ctx, rt.ResourceTypeID, scopeName)
	require.NotNil(s.T(), scopesReturned)
	require.NoError(s.T(), err)
}

func (s *roleManagementServiceBlackboxTest) TestAssertRolesWithAppendingToExistingOK() {
	s.checkAssignRoleOK(true)
}

func (s *roleManagementServiceBlackboxTest) TestAssertRolesWithReplacingExistingOK() {
	s.checkAssignRoleOK(false)
}

func (s *roleManagementServiceBlackboxTest) checkAssignRoleOK(appendToExistingRoles bool) {
	g := s.DBTestSuite.NewTestGraph(s.T())
	newSpace := g.CreateSpace()
	adminUser := g.CreateUser("adminuser-who-adds-the-others")
	newSpace.AddAdmin(adminUser)

	var allUsersToBeAssigned []uuid.UUID
	var usersToBeAssignedAsAdmin []uuid.UUID
	var usersToBeAssignedAsContributor []uuid.UUID
	// Assign Admin role to 5 users
	for i := 0; i < 5; i++ {
		userToBeAssigned := g.CreateUser()
		newSpace.AddViewer(userToBeAssigned)
		usersToBeAssignedAsAdmin = append(usersToBeAssignedAsAdmin, userToBeAssigned.Identity().ID)
		allUsersToBeAssigned = append(allUsersToBeAssigned, userToBeAssigned.Identity().ID)
	}
	// Also assign Contributor role to the other 5 users
	for i := 0; i < 5; i++ {
		userToBeAssigned := g.CreateUser()
		newSpace.AddViewer(userToBeAssigned)
		usersToBeAssignedAsContributor = append(usersToBeAssignedAsContributor, userToBeAssigned.Identity().ID)
		allUsersToBeAssigned = append(allUsersToBeAssigned, userToBeAssigned.Identity().ID)
	}
	// And one more user with both Admin and Contributor roles
	userToBeAssigned := g.CreateUser()
	newSpace.AddViewer(userToBeAssigned)
	usersToBeAssignedAsAdmin = append(usersToBeAssignedAsAdmin, userToBeAssigned.Identity().ID)
	usersToBeAssignedAsContributor = append(usersToBeAssignedAsContributor, userToBeAssigned.Identity().ID)
	allUsersToBeAssigned = append(allUsersToBeAssigned, userToBeAssigned.Identity().ID)

	roleAssignments := make(map[string][]uuid.UUID)
	roleAssignments[authorization.SpaceAdminRole] = usersToBeAssignedAsAdmin
	roleAssignments[authorization.SpaceContributorRole] = usersToBeAssignedAsContributor

	err := s.service.Assign(context.Background(), adminUser.Identity().ID, roleAssignments, newSpace.SpaceID(), appendToExistingRoles)
	require.NoError(s.T(), err)

	s.addNoisyAssignments()

	// Check the new Admin roles were assigned
	usersToBeAssertedPlusAdmin := append(usersToBeAssignedAsAdmin, adminUser.Identity().ID)
	s.checkRoleAssignments(usersToBeAssertedPlusAdmin, authorization.SpaceAdminRole, newSpace.SpaceID())

	// Check the new Contributor roles were assigned
	s.checkRoleAssignments(usersToBeAssignedAsContributor, authorization.SpaceContributorRole, newSpace.SpaceID())

	// Check the old roles were deleted or still present depending on appendToExistingRoles param
	oldAssignedViewerRoles, err := s.Application.IdentityRoleRepository().FindIdentityRolesByResourceAndRoleName(context.Background(), newSpace.SpaceID(), authorization.SpaceViewerRole, false)
	require.NoError(s.T(), err)
	if !appendToExistingRoles {
		// Check that the old view roles are now deleted from the the users for the resource
		assert.Len(s.T(), oldAssignedViewerRoles, 0)
	} else {
		// Check that the old view roles are are still present
		assert.Len(s.T(), oldAssignedViewerRoles, 11)
		validateAssignee(s.T(), allUsersToBeAssigned, newSpace.SpaceID(), oldAssignedViewerRoles)
	}
}

func (s *roleManagementServiceBlackboxTest) checkRoleAssignments(identities []uuid.UUID, roleName, resourceID string) {
	newAssignedRoles, err := s.Application.IdentityRoleRepository().FindIdentityRolesByResourceAndRoleName(context.Background(), resourceID, roleName, false)
	require.NoError(s.T(), err)
	require.Len(s.T(), newAssignedRoles, len(identities))

	validateAssignee(s.T(), identities, resourceID, newAssignedRoles)
}

func (s *roleManagementServiceBlackboxTest) addNoisyAssignments() {
	g := s.DBTestSuite.NewTestGraph(s.T())
	for i := 0; i < 10; i++ {
		randomAssignee := g.CreateUser()
		g.CreateSpace().AddContributor(randomAssignee)
	}
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleWithLackOfPermissionsFails() {
	g := s.DBTestSuite.NewTestGraph(s.T())
	newSpace := g.CreateSpace()
	viewer := g.CreateUser("viewer-who-tries-to-assign-roles")
	newSpace.AddViewer(viewer)

	userToBeAssigned := g.CreateUser()
	newSpace.AddViewer(userToBeAssigned)

	roleAssignments := make(map[string][]uuid.UUID)
	roleAssignments[authorization.SpaceAdminRole] = []uuid.UUID{userToBeAssigned.Identity().ID}

	err := s.service.Assign(context.Background(), viewer.Identity().ID, roleAssignments, newSpace.SpaceID(), false)
	testsupport.AssertError(s.T(), err, errors.ForbiddenError{}, "identity with ID %s does not have required scope manage for resource %s", viewer.Identity().ID.String(), newSpace.SpaceID())
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleAlreadyExists() {
	g := s.DBTestSuite.NewTestGraph(s.T())
	spaceAdmin := g.CreateUser("adminuser")
	newSpace := g.CreateSpace().AddAdmin(spaceAdmin)

	roleAssignments := make(map[string][]uuid.UUID)
	userToBeAssigned := g.CreateUser()
	newSpace.AddContributor(userToBeAssigned).AddAdmin(userToBeAssigned)

	// We've already assigned the contributor and admin roles, lets try to add the admin role again
	roleAssignments[authorization.SpaceAdminRole] = []uuid.UUID{userToBeAssigned.Identity().ID}
	err := s.service.Assign(context.Background(), spaceAdmin.Identity().ID, roleAssignments, newSpace.SpaceID(), true)
	require.Error(s.T(), err)
	require.IsType(s.T(), errors.DataConflictError{}, errs.Cause(err))
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleResourceNotFound() {
	g := s.DBTestSuite.NewTestGraph(s.T())
	identityID := g.CreateUser().Identity().ID
	userToBeAdded := []uuid.UUID{g.CreateUser("randomuser").Identity().ID}
	roleAssignments := make(map[string][]uuid.UUID)
	roleAssignments[authorization.SpaceContributorRole] = userToBeAdded

	err := s.service.Assign(context.Background(), identityID, roleAssignments, uuid.NewV4().String(), false)
	require.IsType(s.T(), errors.NotFoundError{}, errs.Cause(err))
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleWithRoleNotFound() {
	g := s.DBTestSuite.NewTestGraph(s.T())
	adminUser := g.CreateUser()
	newSpace := g.CreateSpace().AddAdmin(adminUser)
	userToBeAdded := []uuid.UUID{g.CreateUser("randomuser").Identity().ID}
	roleAssignments := make(map[string][]uuid.UUID)
	roleAssignments[uuid.NewV4().String()] = userToBeAdded

	err := s.service.Assign(context.Background(), adminUser.Identity().ID, roleAssignments, newSpace.SpaceID(), false)
	require.IsType(s.T(), errors.NotFoundError{}, errs.Cause(err))
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleWithIdentityNotFound() {
	g := s.DBTestSuite.NewTestGraph(s.T())
	adminUser := g.CreateUser()
	newSpace := g.CreateSpace().AddAdmin(adminUser)
	userToBeAdded := []uuid.UUID{uuid.NewV4()}
	roleAssignments := make(map[string][]uuid.UUID)
	roleAssignments[authorization.SpaceAdminRole] = userToBeAdded

	err := s.service.Assign(context.Background(), adminUser.Identity().ID, roleAssignments, newSpace.SpaceID(), false)
	require.IsType(s.T(), errors.BadParameterError{}, errs.Cause(err))
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleAsAdminOK() {
	g := s.DBTestSuite.NewTestGraph(s.T())
	newSpace := g.CreateSpace()
	spaceCreator := g.CreateUser()
	s.addNoisyAssignments()

	err := s.service.ForceAssign(context.Background(), spaceCreator.Identity().ID, authorization.SpaceAdminRole, *newSpace.Resource())
	require.NoError(s.T(), err)

	// Check the role was assigned
	s.checkRoleAssignments([]uuid.UUID{spaceCreator.Identity().ID}, "admin", newSpace.SpaceID())
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleAsAdminFailsExistingAssignment() {
	newSpace := s.Graph.CreateSpace()
	spaceCreator := s.Graph.CreateUser()
	s.addNoisyAssignments()

	err := s.service.ForceAssign(context.Background(), spaceCreator.Identity().ID, authorization.SpaceAdminRole, *newSpace.Resource())
	require.NoError(s.T(), err)

	// Check the role was assigned
	s.checkRoleAssignments([]uuid.UUID{spaceCreator.Identity().ID}, "admin", newSpace.SpaceID())

	err = s.service.ForceAssign(context.Background(), spaceCreator.Identity().ID, authorization.SpaceAdminRole, *newSpace.Resource())
	require.Error(s.T(), err)
	require.IsType(s.T(), errors.DataConflictError{}, errs.Cause(err))

}

func (s *roleManagementServiceBlackboxTest) TestAssignUnknownRoleAsAdminFails() {
	g := s.DBTestSuite.NewTestGraph(s.T())
	newSpace := g.CreateSpace()
	spaceCreator := g.CreateUser()

	err := s.service.ForceAssign(context.Background(), spaceCreator.Identity().ID, "unknownRole", *newSpace.Resource())
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "role with name 'unknownRole' not found")
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleAsAdminToUnknownIdentityFails() {
	g := s.DBTestSuite.NewTestGraph(s.T())
	newSpace := g.CreateSpace()
	id := uuid.NewV4()

	err := s.service.ForceAssign(context.Background(), id, authorization.SpaceAdminRole, *newSpace.Resource())
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "identity with id '%s' not found", id)
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleAsAdminForUnknownResourceFails() {
	g := s.DBTestSuite.NewTestGraph(s.T())
	spaceCreator := g.CreateUser()
	id := uuid.NewV4().String()

	// Should fail because of there is no "admin" role for an unknown resource type
	err := s.service.ForceAssign(context.Background(), spaceCreator.Identity().ID, authorization.SpaceAdminRole, resource.Resource{})
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "role with name 'admin' not found")

	// Should fail because of unknown resource ID
	err = s.service.ForceAssign(context.Background(), spaceCreator.Identity().ID, authorization.SpaceAdminRole, resource.Resource{ResourceID: id, ResourceType: resourcetype.ResourceType{Name: authorization.ResourceTypeSpace}})
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "resource with id '%s' not found", id)
}

func (s *roleManagementServiceBlackboxTest) TestRevokeResourceRolesForUnknownResourceOrUserFails() {
	admin := s.Graph.CreateUser()
	toDelete := s.Graph.CreateUser()
	space := s.Graph.CreateSpace().AddAdmin(admin).AddContributor(toDelete)
	unknownID := uuid.NewV4()

	err := s.service.RevokeResourceRoles(s.Ctx, admin.IdentityID(), []uuid.UUID{toDelete.IdentityID()}, unknownID.String())
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "resource with id '%s' not found", unknownID.String())

	err = s.service.RevokeResourceRoles(s.Ctx, admin.IdentityID(), []uuid.UUID{unknownID}, space.SpaceID())
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "identity_role with resource_id '%s' and identity_id '%s' not found", space.SpaceID(), unknownID.String())
}

func (s *roleManagementServiceBlackboxTest) TestRevokeResourceRolesByUserWithLackOfPermissionsFails() {
	notAdmin := s.Graph.CreateUser()
	toDelete := s.Graph.CreateUser()
	space := s.Graph.CreateSpace().AddContributor(notAdmin).AddContributor(s.Graph.CreateUser(toDelete))

	err := s.service.RevokeResourceRoles(s.Ctx, notAdmin.IdentityID(), []uuid.UUID{toDelete.IdentityID()}, space.SpaceID())
	testsupport.AssertError(s.T(), err, errors.ForbiddenError{}, "identity with ID %s does not have required scope manage for resource %s", notAdmin.IdentityID(), space.SpaceID())

	unknownID := uuid.NewV4()
	err = s.service.RevokeResourceRoles(s.Ctx, unknownID, []uuid.UUID{toDelete.IdentityID()}, space.SpaceID())
	testsupport.AssertError(s.T(), err, errors.ForbiddenError{}, "identity with ID %s does not have required scope manage for resource %s", unknownID.String(), space.SpaceID())
}

func (s *roleManagementServiceBlackboxTest) TestRevokeResourceRolesOK() {
	// Test space
	space := s.Graph.CreateSpace()
	// One viewer/contributor in the space to stay
	userToStay := s.Graph.CreateUser()
	space.AddViewer(userToStay).AddContributor(userToStay)
	admin := s.Graph.CreateUser()
	space.AddAdmin(admin)

	// Viewers/contributors in the space which roles we want to delete
	var usersToDelete []uuid.UUID
	for i := 0; i < 5; i++ {
		u := s.Graph.CreateUser()
		usersToDelete = append(usersToDelete, u.IdentityID())
		space.AddViewer(u).AddContributor(u)
	}
	// One admin to delete
	u := s.Graph.CreateUser()
	usersToDelete = append(usersToDelete, u.IdentityID())
	space.AddAdmin(u)

	// Make some noise
	spaceX := s.Graph.CreateSpace()
	for i := 0; i < 5; i++ {
		spaceX.AddViewer(s.Graph.CreateUser()).AddContributor(s.Graph.CreateUser())
	}

	// Revoke the roles
	err := s.service.RevokeResourceRoles(s.Ctx, admin.IdentityID(), usersToDelete, space.SpaceID())
	require.NoError(s.T(), err)

	// Check the identity roles for the space and users are gone
	for _, idn := range usersToDelete {
		idRoles, err := s.Application.IdentityRoleRepository().FindIdentityRolesByIdentityAndResource(s.Ctx, space.SpaceID(), idn)
		require.NoError(s.T(), err)
		assert.Len(s.T(), idRoles, 0)
	}

	// Check the identity roles for the other users for this space are still preset
	idRoles, err := s.Application.IdentityRoleRepository().FindIdentityRolesByIdentityAndResource(s.Ctx, space.SpaceID(), userToStay.Identity().ID)
	require.NoError(s.T(), err)
	assert.Len(s.T(), idRoles, 2)
	idRoles, err = s.Application.IdentityRoleRepository().FindIdentityRolesByIdentityAndResource(s.Ctx, space.SpaceID(), admin.Identity().ID)
	require.NoError(s.T(), err)
	assert.Len(s.T(), idRoles, 1)

	// Check the identity roles for the other space are still preset
	idRoles, err = s.Application.IdentityRoleRepository().FindIdentityRolesByResource(s.Ctx, spaceX.SpaceID(), false)
	require.NoError(s.T(), err)
	assert.Len(s.T(), idRoles, 10)
}

func (s *roleManagementServiceBlackboxTest) TestPrivilegeCacheNotified() {
	// Create a new resource type
	rt := s.Graph.CreateResourceType()
	rt.AddScope("manage")
	rt.AddScope("foo")
	rt.AddScope("bar")
	rt.AddScope("charlie")

	// Create an admin role
	adminRole := s.Graph.CreateRole(rt, "admin")
	adminRole.AddScope("manage")

	// Create a role with scope "foo"
	r1 := s.Graph.CreateRole(rt, "fooRole")
	r1.AddScope("foo")

	// Create a role with scope "bar"
	r2 := s.Graph.CreateRole(rt, "barRole")
	r2.AddScope("bar")

	// Create a new resource
	res := s.Graph.CreateResource(rt)

	// Create an admin user
	admin := s.Graph.CreateUser()

	// Read the privilege cache for the admin scopes
	privs, err := s.Application.PrivilegeCacheService().CachedPrivileges(s.Ctx, admin.IdentityID(), res.ResourceID())
	require.NoError(s.T(), err)
	// At this stage the admin user should have no scopes
	require.Len(s.T(), privs.ScopesAsArray(), 0)

	// Assign the admin user the admin role for the resource, using the ForceAssign() function
	err = s.Application.RoleManagementService().ForceAssign(s.Ctx, admin.IdentityID(), "admin", *res.Resource())
	require.NoError(s.T(), err)

	// Now the admin user should have the manage scope
	privs, err = s.Application.PrivilegeCacheService().CachedPrivileges(s.Ctx, admin.IdentityID(), res.ResourceID())
	require.NoError(s.T(), err)
	require.Len(s.T(), privs.ScopesAsArray(), 1)
	require.Contains(s.T(), privs.ScopesAsArray(), "manage")

	// Create a user
	user := s.Graph.CreateUser()

	// Hit the privilege cache
	privs, err = s.Application.PrivilegeCacheService().CachedPrivileges(s.Ctx, user.IdentityID(), res.ResourceID())
	require.NoError(s.T(), err)

	// There should be no privileges assigned at this point in time
	require.Len(s.T(), privs.ScopesAsArray(), 0)

	// Assign a role via the role management service ForceAssign() function
	err = s.Application.RoleManagementService().ForceAssign(s.Ctx, user.IdentityID(), "fooRole", *res.Resource())
	require.NoError(s.T(), err)

	// Hit the privilege cache again
	privs, err = s.Application.PrivilegeCacheService().CachedPrivileges(s.Ctx, user.IdentityID(), res.ResourceID())
	require.NoError(s.T(), err)

	// The user should now have the "foo" scope
	require.Len(s.T(), privs.ScopesAsArray(), 1)
	require.Contains(s.T(), privs.ScopesAsArray(), "foo")

	// Assign a role via the role management service Assign() function
	assignments := map[string][]uuid.UUID{"barRole": {user.IdentityID()}}
	err = s.Application.RoleManagementService().Assign(s.Ctx, admin.IdentityID(), assignments, res.ResourceID(), true)
	require.NoError(s.T(), err)

	// Hit the privilege cache again
	privs, err = s.Application.PrivilegeCacheService().CachedPrivileges(s.Ctx, user.IdentityID(), res.ResourceID())
	require.NoError(s.T(), err)

	// The user should now also have the "bar" scope
	require.Len(s.T(), privs.ScopesAsArray(), 2)
	require.ElementsMatch(s.T(), privs.ScopesAsArray(), []string{"foo", "bar"})

	// Now create a team
	t := s.Graph.CreateTeam()

	// And create an organization
	org := s.Graph.CreateOrganization()

	// Add the team to the organization
	org.AddMember(t)

	// Add the user to the team
	t.AddMember(user)

	// Create another user and add it to the same team
	otherUser := s.Graph.CreateUser()
	t.AddMember(otherUser)

	// Create a new charlie role with scope "charlie"
	charlieRole := s.Graph.CreateRole(rt, "charlieRole")
	charlieRole.AddScope("charlie")

	// Assign the role to the organization
	err = s.Application.RoleManagementService().ForceAssign(s.Ctx, org.OrganizationID(), "charlieRole", *res.Resource())
	require.NoError(s.T(), err)

	// Hit the privilege cache again
	privs, err = s.Application.PrivilegeCacheService().CachedPrivileges(s.Ctx, user.IdentityID(), res.ResourceID())
	require.NoError(s.T(), err)

	// The user should now also have all three scopes
	require.Len(s.T(), privs.ScopesAsArray(), 3)
	require.ElementsMatch(s.T(), privs.ScopesAsArray(), []string{"foo", "bar", "charlie"})

	// Now check the scopes for the other user
	privs, err = s.Application.PrivilegeCacheService().CachedPrivileges(s.Ctx, otherUser.IdentityID(), res.ResourceID())
	require.NoError(s.T(), err)

	// The other user should just have the charlie scope
	require.Len(s.T(), privs.ScopesAsArray(), 1)
	require.Contains(s.T(), privs.ScopesAsArray(), "charlie")

	// Remove the user from the team
	t.RemoveMember(user)

	// Check the privilege cache for the user again
	privs, err = s.Application.PrivilegeCacheService().CachedPrivileges(s.Ctx, user.IdentityID(), res.ResourceID())
	require.NoError(s.T(), err)

	// The user should now only have the foo and bar scopes
	require.Len(s.T(), privs.ScopesAsArray(), 2)
	require.ElementsMatch(s.T(), privs.ScopesAsArray(), []string{"foo", "bar"})

	// Ensure the remaining team member still has the correct scopes
	privs, err = s.Application.PrivilegeCacheService().CachedPrivileges(s.Ctx, otherUser.IdentityID(), res.ResourceID())
	require.NoError(s.T(), err)
	require.Len(s.T(), privs.ScopesAsArray(), 1)
	require.Contains(s.T(), privs.ScopesAsArray(), "charlie")
}

func validateAssignee(t *testing.T, amongUsers []uuid.UUID, resourceID string, returnedAssignedRoles []rolerepo.IdentityRole) {
	for _, returnedAssignment := range returnedAssignedRoles {
		require.Equal(t, resourceID, returnedAssignment.ResourceID)
		foundUser := false
		for _, i := range amongUsers {
			if i == returnedAssignment.IdentityID {
				foundUser = true
			}
		}
		require.True(t, foundUser)
	}
}
