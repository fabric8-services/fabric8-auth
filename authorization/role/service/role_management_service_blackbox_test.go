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
	repo              service.RoleManagementService
	roleRepo          rolerepo.RoleRepository
	resourceTypeScope resourcetype.ResourceTypeScopeRepository
}

func TestRunRoleManagementServiceBlackboxTest(t *testing.T) {
	suite.Run(t, &roleManagementServiceBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *roleManagementServiceBlackboxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = s.Application.RoleManagementService()
	s.roleRepo = rolerepo.NewRoleRepository(s.DB)
	s.resourceTypeScope = resourcetype.NewResourceTypeScopeRepository(s.DB)
}

func (s *roleManagementServiceBlackboxTest) TestGetIdentityRoleByResource() {
	t := s.T()
	identityRole, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRole)

	// something that we dont want to be returned
	identityRoleUnrelated, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRoleUnrelated)

	identityRoles, err := s.repo.ListByResource(s.Ctx, identityRole.Resource.ResourceID)
	require.NoError(t, err)
	require.Len(t, identityRoles, 1)
	require.Equal(t, identityRole.Resource.ResourceID, identityRoles[0].Resource.ResourceID)
	require.Equal(t, identityRole.Identity.ID, identityRoles[0].Identity.ID)
	require.Equal(t, identityRole.Role.RoleID, identityRoles[0].Role.RoleID)
}

func (s *roleManagementServiceBlackboxTest) TestGetIdentityRoleByResourceAndRoleName() {
	t := s.T()
	identityRole, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRole)

	// something that we don't want to be returned
	for i := 0; i < 10; i++ {
		identityRoleUnrelated, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
		require.NoError(t, err)
		require.NotNil(t, identityRoleUnrelated)
	}

	identityRoles, err := s.repo.ListByResourceAndRoleName(s.Ctx, identityRole.Resource.ResourceID, identityRole.Role.Name)
	require.NoError(t, err)
	require.Len(t, identityRoles, 1)
	require.Equal(t, identityRole.Resource.ResourceID, identityRoles[0].Resource.ResourceID)
	require.Equal(t, identityRole.Identity.ID, identityRoles[0].Identity.ID)
	require.Equal(t, identityRole.Role.RoleID, identityRoles[0].Role.RoleID)
}

func (s *roleManagementServiceBlackboxTest) TestGetIdentityRoleByResourceNotFound() {
	t := s.T()
	identityRole, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRole)

	identityRoles, err := s.repo.ListByResource(s.Ctx, uuid.NewV4().String())
	require.NoError(t, err)
	require.Equal(t, 0, len(identityRoles))
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

	roleScopesRetrieved, err := s.repo.ListAvailableRolesByResourceType(s.Ctx, resourceType.Name)
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

	roleScopesRetrieved, err := s.repo.ListAvailableRolesByResourceType(s.Ctx, newResourceTypeName)
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

func (s *roleManagementServiceBlackboxTest) TestGetIdentityRoleByResourceAndRoleNameNotFound() {
	t := s.T()
	identityRole, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRole)

	identityRoles, err := s.repo.ListByResourceAndRoleName(s.Ctx, uuid.NewV4().String(), uuid.NewV4().String())
	require.NoError(t, err)
	require.Equal(t, 0, len(identityRoles))
}

func (s *roleManagementServiceBlackboxTest) TestAssertRolesWithAppendingToExistingOK() {
	s.checkAssignRoleOK(true)
}

func (s *roleManagementServiceBlackboxTest) TestAssertRolesWithReplacingExistingOK() {
	s.checkAssignRoleOK(false)
}

func (s *roleManagementServiceBlackboxTest) checkAssignRoleOK(appendToExistingRoles bool) {
	g := s.DBTestSuite.NewTestGraph()
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

	err := s.repo.Assign(context.Background(), adminUser.Identity().ID, roleAssignments, newSpace.SpaceID(), appendToExistingRoles)
	require.NoError(s.T(), err)

	s.addNoisyAssignments()

	// Check the new Admin roles were assigned
	usersToBeAssertedPlusAdmin := append(usersToBeAssignedAsAdmin, adminUser.Identity().ID)
	s.checkRoleAssignments(usersToBeAssertedPlusAdmin, authorization.SpaceAdminRole, newSpace.SpaceID())

	// Check the new Contributor roles were assigned
	s.checkRoleAssignments(usersToBeAssignedAsContributor, authorization.SpaceContributorRole, newSpace.SpaceID())

	// Check the old roles were deleted or still present depending on appendToExistingRoles param
	oldAssignedViewerRoles, err := s.repo.ListByResourceAndRoleName(context.Background(), newSpace.SpaceID(), authorization.SpaceViewerRole)
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
	newAssignedRoles, err := s.repo.ListByResourceAndRoleName(context.Background(), resourceID, roleName)
	require.NoError(s.T(), err)
	require.Len(s.T(), newAssignedRoles, len(identities))

	validateAssignee(s.T(), identities, resourceID, newAssignedRoles)
}

func (s *roleManagementServiceBlackboxTest) addNoisyAssignments() {
	g := s.DBTestSuite.NewTestGraph()
	for i := 0; i < 10; i++ {
		randomAssignee := g.CreateUser()
		g.CreateSpace().AddContributor(randomAssignee)
	}
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleWithLackOfPermissionsFails() {
	g := s.DBTestSuite.NewTestGraph()
	newSpace := g.CreateSpace()
	viewer := g.CreateUser("viewer-who-tries-to-assign-roles")
	newSpace.AddViewer(viewer)

	userToBeAssigned := g.CreateUser()
	newSpace.AddViewer(userToBeAssigned)

	roleAssignments := make(map[string][]uuid.UUID)
	roleAssignments[authorization.SpaceAdminRole] = []uuid.UUID{userToBeAssigned.Identity().ID}

	err := s.repo.Assign(context.Background(), viewer.Identity().ID, roleAssignments, newSpace.SpaceID(), false)
	testsupport.AssertError(s.T(), err, errors.ForbiddenError{}, "identity with ID %s does not have required scope manage for resource %s", viewer.Identity().ID.String(), newSpace.SpaceID())
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleAlreadyExists() {
	g := s.DBTestSuite.NewTestGraph()
	spaceAdmin := g.CreateUser("adminuser")
	newSpace := g.CreateSpace().AddAdmin(spaceAdmin)

	roleAssignments := make(map[string][]uuid.UUID)
	userToBeAssigned := g.CreateUser()
	newSpace.AddContributor(userToBeAssigned).AddAdmin(userToBeAssigned)
	roleAssignments[authorization.SpaceAdminRole] = []uuid.UUID{userToBeAssigned.Identity().ID}

	// lets try to add the same role again
	err := s.repo.Assign(context.Background(), spaceAdmin.Identity().ID, roleAssignments, newSpace.SpaceID(), false)
	require.Error(s.T(), err)
	require.IsType(s.T(), errors.DataConflictError{}, errs.Cause(err))
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleResourceNotFound() {
	g := s.DBTestSuite.NewTestGraph()
	identityID := g.CreateUser().Identity().ID
	userToBeAdded := []uuid.UUID{g.CreateUser("randomuser").Identity().ID}
	roleAssignments := make(map[string][]uuid.UUID)
	roleAssignments[authorization.SpaceContributorRole] = userToBeAdded

	err := s.repo.Assign(context.Background(), identityID, roleAssignments, uuid.NewV4().String(), false)
	require.IsType(s.T(), errors.NotFoundError{}, errs.Cause(err))
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleWithRoleNotFound() {
	g := s.DBTestSuite.NewTestGraph()
	adminUser := g.CreateUser()
	newSpace := g.CreateSpace().AddAdmin(adminUser)
	userToBeAdded := []uuid.UUID{g.CreateUser("randomuser").Identity().ID}
	roleAssignments := make(map[string][]uuid.UUID)
	roleAssignments[uuid.NewV4().String()] = userToBeAdded

	err := s.repo.Assign(context.Background(), adminUser.Identity().ID, roleAssignments, newSpace.SpaceID(), false)
	require.IsType(s.T(), errors.NotFoundError{}, errs.Cause(err))
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleWithIdentityNotFound() {
	g := s.DBTestSuite.NewTestGraph()
	adminUser := g.CreateUser()
	newSpace := g.CreateSpace().AddAdmin(adminUser)
	userToBeAdded := []uuid.UUID{uuid.NewV4()}
	roleAssignments := make(map[string][]uuid.UUID)
	roleAssignments[authorization.SpaceAdminRole] = userToBeAdded

	err := s.repo.Assign(context.Background(), adminUser.Identity().ID, roleAssignments, newSpace.SpaceID(), false)
	require.IsType(s.T(), errors.BadParameterError{}, errs.Cause(err))
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleAsAdminOK() {
	g := s.DBTestSuite.NewTestGraph()
	newSpace := g.CreateSpace()
	spaceCreator := g.CreateUser()
	s.addNoisyAssignments()

	err := s.repo.ForceAssign(context.Background(), spaceCreator.Identity().ID, authorization.SpaceAdminRole, *newSpace.Resource())
	require.NoError(s.T(), err)

	// Check the role was assigned
	s.checkRoleAssignments([]uuid.UUID{spaceCreator.Identity().ID}, "admin", newSpace.SpaceID())
}

func (s *roleManagementServiceBlackboxTest) TestAssignUnknownRoleAsAdminFails() {
	g := s.DBTestSuite.NewTestGraph()
	newSpace := g.CreateSpace()
	spaceCreator := g.CreateUser()

	err := s.repo.ForceAssign(context.Background(), spaceCreator.Identity().ID, "unknownRole", *newSpace.Resource())
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "role with name 'unknownRole' not found")
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleAsAdminToUnknownIdentityFails() {
	g := s.DBTestSuite.NewTestGraph()
	newSpace := g.CreateSpace()
	id := uuid.NewV4()

	err := s.repo.ForceAssign(context.Background(), id, authorization.SpaceAdminRole, *newSpace.Resource())
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "identity with id '%s' not found", id)
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleAsAdminForUnknownResourceFails() {
	g := s.DBTestSuite.NewTestGraph()
	spaceCreator := g.CreateUser()
	id := uuid.NewV4().String()

	// Should fail because of there is no "admin" role for an unknown resource type
	err := s.repo.ForceAssign(context.Background(), spaceCreator.Identity().ID, authorization.SpaceAdminRole, resource.Resource{})
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "role with name 'admin' not found")

	// Should fail because of unknown resource ID
	err = s.repo.ForceAssign(context.Background(), spaceCreator.Identity().ID, authorization.SpaceAdminRole, resource.Resource{ResourceID: id, ResourceType: resourcetype.ResourceType{Name: authorization.ResourceTypeSpace}})
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "resource with id '%s' not found", id)
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
