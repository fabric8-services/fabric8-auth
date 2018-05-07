package service_test

import (
	"github.com/fabric8-services/fabric8-auth/errors"
	errs "github.com/pkg/errors"
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	rolescope "github.com/fabric8-services/fabric8-auth/authorization/role/service"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"context"
	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type roleManagementServiceBlackboxTest struct {
	gormtestsupport.DBTestSuite
	repo              rolescope.RoleManagementService
	roleRepo          rolerepo.RoleRepository
	resourcetypeRepo  resourcetype.ResourceTypeRepository
	resourceTypeScope resourcetype.ResourceTypeScopeRepository
}

func TestRunRoleManagementServiceBlackboxTest(t *testing.T) {
	suite.Run(t, &roleManagementServiceBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *roleManagementServiceBlackboxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = rolescope.NewRoleManagementService(s.Application, s.Application)
	s.roleRepo = rolerepo.NewRoleRepository(s.DB)
	s.resourcetypeRepo = resourcetype.NewResourceTypeRepository(s.DB)
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
		require.Nil(s.T(), err)

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

func (s *roleManagementServiceBlackboxTest) TestAssignRoleOK() {
	g := s.DBTestSuite.NewTestGraph()
	newSpace := g.CreateSpace(g.ID("myspace"))

	var usersToBeAsserted []uuid.UUID
	for i := 0; i < 10; i++ {
		userToBeAssigned := g.CreateUser(g.ID("adminname"))
		err := s.repo.Assign(context.Background(), userToBeAssigned.Identity().ID, newSpace.SpaceID(), authorization.AdminRole)
		require.Nil(s.T(), err)
		usersToBeAsserted = append(usersToBeAsserted, userToBeAssigned.Identity().ID)
	}

	// noise
	for i := 0; i < 10; i++ {
		err := s.repo.Assign(context.Background(), g.CreateUser(g.ID("adminname")).Identity().ID, g.CreateSpace(g.ID("myspace")).SpaceID(), authorization.AdminRole)
		require.Nil(s.T(), err)
	}

	assignedRoles, err := s.repo.ListByResourceAndRoleName(context.Background(), newSpace.SpaceID(), authorization.AdminRole)
	require.Nil(s.T(), err)
	require.Len(s.T(), assignedRoles, 10)
	validateAssignee(s.T(), usersToBeAsserted, newSpace.SpaceID(), assignedRoles)
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleAlreadyExists() {
	g := s.DBTestSuite.NewTestGraph()
	newSpace := g.CreateSpace(g.ID("myspace"))

	userToBeAssigned := g.CreateUser(g.ID("somename"))
	err := s.repo.Assign(context.Background(), userToBeAssigned.Identity().ID, newSpace.SpaceID(), authorization.AdminRole)
	require.Nil(s.T(), err)

	err = s.repo.Assign(context.Background(), userToBeAssigned.Identity().ID, newSpace.SpaceID(), authorization.AdminRole)
	require.IsType(s.T(), errors.DataConflictError{}, errs.Cause(err))
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleResourceNotFound() {
	err := s.repo.Assign(context.Background(), uuid.NewV4(), uuid.NewV4().String(), uuid.NewV4().String())
	require.IsType(s.T(), errors.NotFoundError{}, errs.Cause(err))
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleWithRoleNotFound() {
	g := s.DBTestSuite.NewTestGraph()
	newSpace := g.CreateSpace(g.ID("myspace"))
	err := s.repo.Assign(context.Background(), uuid.NewV4(), newSpace.SpaceID(), uuid.NewV4().String())
	require.IsType(s.T(), errors.NotFoundError{}, errs.Cause(err))
}

func (s *roleManagementServiceBlackboxTest) TestAssignRoleWithIdentityNotFound() {
	g := s.DBTestSuite.NewTestGraph()
	newSpace := g.CreateSpace(g.ID("myspace"))
	err := s.repo.Assign(context.Background(), uuid.NewV4(), newSpace.SpaceID(), authorization.AdminRole)
	require.IsType(s.T(), errors.NotFoundError{}, errs.Cause(err))
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
