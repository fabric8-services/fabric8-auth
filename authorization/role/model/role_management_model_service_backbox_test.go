package model_test

import (
	"testing"

	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	scope "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/scope/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role"
	rolescope "github.com/fabric8-services/fabric8-auth/authorization/role/model"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"

	//rolescope "github.com/fabric8-services/fabric8-auth/authorization/role/scope/repository"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"

	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/suite"
)

type roleManagementModelServiceBlackboxTest struct {
	gormtestsupport.DBTestSuite
	repo              rolescope.RoleManagementModelService
	roleRepo          rolerepo.RoleRepository
	resourcetypeRepo  resourcetype.ResourceTypeRepository
	resourceTypeScope scope.ResourceTypeScopeRepository
}

func TestRunRoleManagementModelServiceBlackboxTest(t *testing.T) {
	suite.Run(t, &roleManagementModelServiceBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *roleManagementModelServiceBlackboxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = rolescope.NewRoleManagementModelService(s.DB, s.Application)
	s.roleRepo = rolerepo.NewRoleRepository(s.DB)
	s.resourcetypeRepo = resourcetype.NewResourceTypeRepository(s.DB)
	s.resourceTypeScope = scope.NewResourceTypeScopeRepository(s.DB)
}

func (s *roleManagementModelServiceBlackboxTest) TestGetIdentityRoleByResource() {
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

func (s *roleManagementModelServiceBlackboxTest) TestGetIdentityRoleByResourceAndRoleName() {
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

func (s *roleManagementModelServiceBlackboxTest) TestGetIdentityRoleByResourceNotFound() {
	t := s.T()
	identityRole, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRole)

	identityRoles, err := s.repo.ListByResource(s.Ctx, uuid.NewV4().String())
	require.NoError(t, err)
	require.Equal(t, 0, len(identityRoles))
}

func (s *roleManagementModelServiceBlackboxTest) TestGetRolesByResourceTypeOK() {

	var createdRoleScopes []rolerepo.RoleScope

	role, err := testsupport.CreateTestRoleWithDefaultType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), role)

	scope, err := testsupport.CreateTestScopeWithDefaultType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), scope)

	rs, err := testsupport.CreateTestRoleScope(s.Ctx, s.DB, *scope, *role)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rs)

	createdRoleScopes = append(createdRoleScopes, *rs)

	areaResourceType, err := s.resourcetypeRepo.Lookup(s.Ctx, "openshift.io/resource/area")
	require.NoError(s.T(), err)
	require.NotNil(s.T(), areaResourceType)

	roleScopesRetrieved, err := s.repo.ListAvailableRolesByResourceType(s.Ctx, "openshift.io/resource/area")
	require.NoError(s.T(), err)

	// there might be other 'RoleScopes' returned too.
	// That wouldn't be considered to be a failure, rather we are gonna check whether they all
	// belong to the same resource type.
	s.checkRoleBelongsToResourceType(s.DB, roleScopesRetrieved, *areaResourceType)

	// Then let's check if the ones we created are there.
	s.checkIfCreatedRoleScopesAreReturned(s.DB, roleScopesRetrieved, createdRoleScopes)
}

func (s *roleManagementModelServiceBlackboxTest) TestGetRolesByResourceTypeOKEmpty() {

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

func (s *roleManagementModelServiceBlackboxTest) checkIfCreatedRoleScopesAreReturned(db *gorm.DB, roleScopesRetrieved []role.RoleScope, createdRoleScopes []rolerepo.RoleScope) {
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

func (s *roleManagementModelServiceBlackboxTest) checkRoleBelongsToResourceType(db *gorm.DB, roleScopesRetrieved []role.RoleScope, rt resourcetype.ResourceType) {
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

func (s *roleManagementModelServiceBlackboxTest) checkScopeBelongsToResourceType(db *gorm.DB, scopeName string, rt resourcetype.ResourceType) {
	scopesReturned, err := s.resourceTypeScope.LookupByResourceTypeAndScope(s.Ctx, rt.ResourceTypeID, scopeName)
	require.NotNil(s.T(), scopesReturned)
	require.NoError(s.T(), err)
}

func (s *roleManagementModelServiceBlackboxTest) TestGetIdentityRoleByResourceAndRoleNameNotFound() {
	t := s.T()
	identityRole, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRole)

	identityRoles, err := s.repo.ListByResourceAndRoleName(s.Ctx, uuid.NewV4().String(), uuid.NewV4().String())
	require.NoError(t, err)
	require.Equal(t, 0, len(identityRoles))
}

func (s *roleManagementModelServiceBlackboxTest) TestAssignRoleOK() {
	t := s.T()

	testIdentity, err := testsupport.CreateTestIdentityAndUser(s.DB, uuid.NewV4().String(), "KC")
	require.NoError(t, err)

	testRT, err := testsupport.CreateTestResourceType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(t, err)
	require.NotNil(t, testRT)

	testRole, err := testsupport.CreateTestRole(s.Ctx, s.DB, *testRT, uuid.NewV4().String())
	require.NoError(t, err)
	require.NotNil(t, testRole)

	testR, err := testsupport.CreateTestResource(s.Ctx, s.DB, *testRT, uuid.NewV4().String(), nil)
	require.NoError(t, err)
	require.NotNil(t, testR)

	err = s.repo.Assign(s.Ctx, testIdentity.ID, testR.ResourceID, testRole.Name)
	require.NoError(t, err)

	identityRoles, err := s.repo.ListByResourceAndRoleName(s.Ctx, testR.ResourceID, testRole.Name)
	require.NoError(t, err)
	require.Equal(t, 1, len(identityRoles))
	require.Equal(t, testR.ResourceID, identityRoles[0].ResourceID)
	require.Equal(t, testRole.RoleID, identityRoles[0].RoleID)
}
