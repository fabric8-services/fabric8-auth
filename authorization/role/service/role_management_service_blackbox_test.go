package service_test

import (
	"testing"

	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	scope "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/scope/repository"
	identityrole "github.com/fabric8-services/fabric8-auth/authorization/role/identityrole/repository"
	rolemodel "github.com/fabric8-services/fabric8-auth/authorization/role/model"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	scoperepo "github.com/fabric8-services/fabric8-auth/authorization/role/scope/repository"
	roleservice "github.com/fabric8-services/fabric8-auth/authorization/role/service"

	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type roleManagementServiceBlackboxTest struct {
	gormtestsupport.DBTestSuite
	roleManagementService roleservice.RoleManagementService
	resourceTypeRepo      resourcetype.ResourceTypeRepository
	roleRepo              rolerepo.RoleRepository
	resourceTypeScope     scope.ResourceTypeScopeRepository
}

func TestRunRoleManagementServiceBlackboxTest(t *testing.T) {
	suite.Run(t, &roleManagementServiceBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *roleManagementServiceBlackboxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	modelService := rolemodel.NewRoleManagementModelService(s.DB, s.Application)
	s.roleManagementService = roleservice.NewRoleManagementService(modelService, s.Application)
	s.resourceTypeRepo = resourcetype.NewResourceTypeRepository(s.DB)
	s.roleRepo = rolerepo.NewRoleRepository(s.DB)
	s.resourceTypeScope = scope.NewResourceTypeScopeRepository(s.DB)

}
func (s *roleManagementServiceBlackboxTest) TestGetIdentityRoleByResource() {
	t := s.T()
	identityRole, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRole)

	identityRoles, err := s.roleManagementService.ListByResource(s.Ctx, identityRole.Resource.ResourceID)
	require.NoError(t, err)
	require.Equal(t, true, len(identityRoles) == 1)
	require.Equal(t, identityRole.Resource.ResourceID, identityRoles[0].Resource.ResourceID)
}

func (s *roleManagementServiceBlackboxTest) TestGetMultipleIdentityRoleByResourceInherited() {

	/*
		Create resource "AreaDev"
		Create child resource "AreaAuth"

		Create 1 assigned role for "AreaDev"
		Create 2 assigned roles for "AreaAuth"

		List all roles for "AreaAuth" : Should return the above 3 assigned roles.
	*/

	t := s.T()
	resourceOwner := testsupport.TestIdentity2
	err := testsupport.CreateTestIdentityAndUserInDB(s.DB, &resourceOwner)
	require.NoError(s.T(), err)

	areaResourceType, err := s.Application.ResourceTypeRepository().Lookup(s.Ctx, "openshift.io/resource/area")
	require.NoError(s.T(), err)

	parentResourceRef, err := testsupport.CreateTestResource(s.Ctx, s.DB, *areaResourceType, "AreaDev", nil)
	require.NoError(s.T(), err)

	resourceRef, err := testsupport.CreateTestResource(s.Ctx, s.DB, *areaResourceType, "AreaAuth", &parentResourceRef.ResourceID)
	require.NoError(s.T(), err)

	roleRef, err := testsupport.CreateTestRole(s.Ctx, s.DB, *areaResourceType, "collab")
	require.NoError(s.T(), err)

	var createdIdentityRoles []identityrole.IdentityRole

	// creating an AssignedRole for a parent resource
	identityRoleRefUnrelated, err := testsupport.CreateTestIdentityRole(s.Ctx, s.DB, *parentResourceRef, *roleRef)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), identityRoleRefUnrelated)

	// creating an AssignedRole for an child resource
	identityRoleRef1, err := testsupport.CreateTestIdentityRole(s.Ctx, s.DB, *resourceRef, *roleRef)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), identityRoleRef1)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef1)

	// creating an AssignedRole for an child resource
	identityRoleRef2, err := testsupport.CreateTestIdentityRole(s.Ctx, s.DB, *resourceRef, *roleRef)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), identityRoleRef1)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef2)

	identityRoles, err := s.roleManagementService.ListByResource(s.Ctx, identityRoleRef1.Resource.ResourceID)
	require.NoError(t, err)
	require.Len(t, identityRoles, 3)
	require.Equal(t, true, s.checkExists(*identityRoleRef1, identityRoles, true))
	require.Equal(t, true, s.checkExists(*identityRoleRef2, identityRoles, true))
	require.Equal(t, true, s.checkExists(*identityRoleRefUnrelated, identityRoles, false))

}

func (s *roleManagementServiceBlackboxTest) TestGetIdentityRolesOfParentResource() {

	/*
		Create resource "AreaDev"
		Create child resource "AreaAuth"

		Create 1 assigned role for "AreaDev"
		Create 2 assigned roles for "AreaAuth"

		List all roles for "AreaDev" : Should return the just 1 assigned role.
	*/

	t := s.T()
	resourceOwner := testsupport.TestIdentity2
	err := testsupport.CreateTestIdentityAndUserInDB(s.DB, &resourceOwner)
	require.NoError(s.T(), err)

	areaResourceType, err := s.Application.ResourceTypeRepository().Lookup(s.Ctx, "openshift.io/resource/area")
	require.NoError(s.T(), err)

	parentResourceRef, err := testsupport.CreateTestResource(s.Ctx, s.DB, *areaResourceType, "AreaDev", nil)
	require.NoError(s.T(), err)

	resourceRef, err := testsupport.CreateTestResource(s.Ctx, s.DB, *areaResourceType, "AreaAuth", &parentResourceRef.ResourceID)
	require.NoError(s.T(), err)

	roleRef, err := testsupport.CreateTestRole(s.Ctx, s.DB, *areaResourceType, "collab")
	require.NoError(s.T(), err)

	var createdIdentityRoles []identityrole.IdentityRole

	// creating an AssignedRole for a parent resource
	identityRoleRefUnrelated, err := testsupport.CreateTestIdentityRole(s.Ctx, s.DB, *parentResourceRef, *roleRef)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), identityRoleRefUnrelated)

	// creating an AssignedRole for an inherited resource
	identityRoleRef1, err := testsupport.CreateTestIdentityRole(s.Ctx, s.DB, *resourceRef, *roleRef)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), identityRoleRef1)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef1)

	// creating an AssignedRole for an inherited resource
	identityRoleRef2, err := testsupport.CreateTestIdentityRole(s.Ctx, s.DB, *resourceRef, *roleRef)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), identityRoleRef1)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef2)

	identityRoles, err := s.roleManagementService.ListByResource(s.Ctx, identityRoleRefUnrelated.Resource.ResourceID)
	require.NoError(t, err)
	require.Len(t, identityRoles, 1)
	require.Equal(t, true, s.checkExists(*identityRoleRefUnrelated, identityRoles, false))

}

func (s *roleManagementServiceBlackboxTest) TestGetMultipleIdentityRoleByResourceNotInherited() {
	t := s.T()
	resourceOwner := testsupport.TestIdentity2
	err := testsupport.CreateTestIdentityAndUserInDB(s.DB, &resourceOwner)
	require.NoError(s.T(), err)

	areaResourceType, err := s.Application.ResourceTypeRepository().Lookup(s.Ctx, "openshift.io/resource/area")
	require.NoError(s.T(), err)

	resourceRef, err := testsupport.CreateTestResource(s.Ctx, s.DB, *areaResourceType, "SpaceR", nil)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), resourceRef)

	resourceRefUnrelated, err := testsupport.CreateTestResource(s.Ctx, s.DB, *areaResourceType, "SpaceRUnrelated", nil)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), resourceRefUnrelated)

	roleRef, err := testsupport.CreateTestRole(s.Ctx, s.DB, *areaResourceType, "collab")
	require.NoError(s.T(), err)

	var createdIdentityRoles []identityrole.IdentityRole

	// creating an AssignedRole for a different resource - not expected
	// to show up in search results.
	identityRoleRefUnrelated, err := testsupport.CreateTestIdentityRole(s.Ctx, s.DB, *resourceRefUnrelated, *roleRef)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), identityRoleRefUnrelated)

	// creating an AssignedRole for a specific resource
	// which will be queried for listing all assigned roles
	identityRoleRef1, err := testsupport.CreateTestIdentityRole(s.Ctx, s.DB, *resourceRef, *roleRef)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), identityRoleRef1)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef1)

	// creating an AssignedRole for a specific resource
	// which will be queried for listing all assigned roles
	identityRoleRef2, err := testsupport.CreateTestIdentityRole(s.Ctx, s.DB, *resourceRef, *roleRef)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), identityRoleRef1)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef2)

	identityRoles, err := s.roleManagementService.ListByResource(s.Ctx, identityRoleRef1.Resource.ResourceID)
	require.NoError(t, err)
	require.Len(t, identityRoles, 2)
	require.Equal(t, true, s.checkExists(*identityRoleRef1, identityRoles, false))
	require.Equal(t, true, s.checkExists(*identityRoleRef2, identityRoles, false))

}

func (s *roleManagementServiceBlackboxTest) TestGetIdentityRoleByResourceNotFound() {
	t := s.T()
	identityRole, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRole)

	identityRoles, err := s.roleManagementService.ListByResource(s.Ctx, uuid.NewV4().String())
	require.Error(t, errors.NotFoundError{})
	require.Equal(t, 0, len(identityRoles))
}

func (s *roleManagementServiceBlackboxTest) checkExists(createdRole identityrole.IdentityRole, pool []identityrole.IdentityRole, isInherited bool) bool {
	for _, retrievedRole := range pool {
		if retrievedRole.IdentityRoleID.String() == createdRole.IdentityRoleID.String() {
			s.compare(createdRole, retrievedRole, isInherited)
			return true
		}
	}
	return false
}

func (s *roleManagementServiceBlackboxTest) compare(createdRole identityrole.IdentityRole, retrievedRole identityrole.IdentityRole, isInherited bool) bool {
	require.Equal(s.T(), createdRole.IdentityRoleID.String(), retrievedRole.IdentityRoleID.String())
	require.Equal(s.T(), createdRole.IdentityID.String(), retrievedRole.Identity.ID.String())
	require.Equal(s.T(), createdRole.Role.Name, retrievedRole.Role.Name)

	if isInherited {
		require.NotNil(s.T(), createdRole.Resource.ParentResourceID)
		require.Equal(s.T(), *createdRole.Resource.ParentResourceID, *retrievedRole.Resource.ParentResourceID)
	} else {
		require.Nil(s.T(), retrievedRole.Resource.ParentResourceID)
	}

	return true
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

	roleScopesRetrieved, err := s.roleManagementService.ListAvailableRolesByResourceType(s.Ctx, newResourceTypeName)
	require.NoError(s.T(), err)
	require.Len(s.T(), roleScopesRetrieved, 0)
}

func (s *roleManagementServiceBlackboxTest) TestGetRolesByNewResourceType() {

	var createdRoleScopes []scoperepo.RoleScope

	newResourceTypeName := uuid.NewV4().String()
	testResourceTypeRef, err := testsupport.CreateTestResourceType(s.Ctx, s.DB, newResourceTypeName)
	require.NoError(s.T(), err)

	for i := 0; i < 10; i++ {
		role, err := testsupport.CreateTestRole(s.Ctx, s.DB, *testResourceTypeRef, uuid.NewV4().String())

		require.NoError(s.T(), err)
		require.NotNil(s.T(), role)

		scope, err := testsupport.CreateTestScope(s.Ctx, s.DB, *testResourceTypeRef, uuid.NewV4().String())
		require.NoError(s.T(), err)
		require.NotNil(s.T(), scope)

		rs, err := testsupport.CreateTestRoleScope(s.Ctx, s.DB, *scope, *role)
		require.NoError(s.T(), err)
		require.NotNil(s.T(), rs)

		createdRoleScopes = append(createdRoleScopes, *rs)
	}

	someOtherResourceType, err := testsupport.CreateTestResourceType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)

	for i := 0; i < 3; i++ {
		role, err := testsupport.CreateTestRole(s.Ctx, s.DB, *someOtherResourceType, uuid.NewV4().String())

		require.NoError(s.T(), err)
		require.NotNil(s.T(), role)

		scope, err := testsupport.CreateTestScope(s.Ctx, s.DB, *someOtherResourceType, uuid.NewV4().String())
		require.NoError(s.T(), err)
		require.NotNil(s.T(), scope)

		rs, err := testsupport.CreateTestRoleScope(s.Ctx, s.DB, *scope, *role)
		require.NoError(s.T(), err)
		require.NotNil(s.T(), rs)
	}

	roleScopesRetrieved, err := s.roleManagementService.ListAvailableRolesByResourceType(s.Ctx, testResourceTypeRef.Name)
	require.NoError(s.T(), err)
	require.Len(s.T(), roleScopesRetrieved, 10)
	s.checkRoleBelongsToResourceType(s.DB, roleScopesRetrieved, *testResourceTypeRef)
	s.checkIfCreatedRoleScopesAreReturned(s.DB, createdRoleScopes, roleScopesRetrieved)

}

func (s *roleManagementServiceBlackboxTest) checkIfCreatedRoleScopesAreReturned(db *gorm.DB, createdRoleScopes []scoperepo.RoleScope, roleScopesRetrieved []rolemodel.RoleScope) {
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
	}
	require.True(s.T(), foundCreatedRoleScope)
}

func (s *roleManagementServiceBlackboxTest) checkRoleBelongsToResourceType(db *gorm.DB, roleScopesRetrieved []rolemodel.RoleScope, rt resourcetype.ResourceType) {
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
			foundScope, err := s.checkScopeBelongsToResourceType(s.DB, sc, rt)
			require.NoError(s.T(), err)
			require.Equal(s.T(), true, foundScope)
		}
	}
}

func (s *roleManagementServiceBlackboxTest) checkScopeBelongsToResourceType(db *gorm.DB, scopeName string, rt resourcetype.ResourceType) (bool, error) {
	scopesReturned, err := s.resourceTypeScope.ListByName(s.Ctx, scopeName)
	if err != nil {
		return false, err
	}
	foundScope := false
	for _, returnedScope := range scopesReturned {
		if returnedScope.ResourceTypeID.String() == rt.ResourceTypeID.String() {
			foundScope = true
		}
	}
	return foundScope, nil
}
