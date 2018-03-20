package service_test

import (
	"testing"

	identityrole "github.com/fabric8-services/fabric8-auth/authorization/role/identityrole/repository"
	rolemodel "github.com/fabric8-services/fabric8-auth/authorization/role/model"
	roleservice "github.com/fabric8-services/fabric8-auth/authorization/role/service"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/goadesign/goa/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type roleManagementServiceBlackboxTest struct {
	gormtestsupport.DBTestSuite
	roleManagementService roleservice.RoleManagementService
}

func TestRunRoleManagementServiceBlackboxTest(t *testing.T) {
	suite.Run(t, &roleManagementServiceBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *roleManagementServiceBlackboxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	modelService := rolemodel.NewRoleManagementModelService(s.DB, s.Application)
	s.roleManagementService = roleservice.NewRoleManagementService(modelService, s.Application)
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

func (s *roleManagementServiceBlackboxTest) TestGetIdentityRolesByRoleNameOK() {

	/*
		Create resource "AreaDev"
		Create resource "AreaAuth"

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

	resourceRef, err := testsupport.CreateTestResource(s.Ctx, s.DB, *areaResourceType, "AreaAuth", nil)
	require.NoError(s.T(), err)

	roleRef, err := testsupport.CreateTestRole(s.Ctx, s.DB, *areaResourceType, "collab")
	require.NoError(s.T(), err)

	roleRef2, err := testsupport.CreateTestRole(s.Ctx, s.DB, *areaResourceType, "collabx")
	require.NoError(s.T(), err)

	var createdIdentityRoles []identityrole.IdentityRole
	var createdIdentityRoles2 []identityrole.IdentityRole

	// role 1

	identityRoleRef1ForRole2, err := testsupport.CreateTestIdentityRole(s.Ctx, s.DB, *resourceRef, *roleRef2)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), identityRoleRef1ForRole2)
	createdIdentityRoles2 = append(createdIdentityRoles2, *identityRoleRef1ForRole2)

	identityRoleRef2ForRole2, err := testsupport.CreateTestIdentityRole(s.Ctx, s.DB, *resourceRef, *roleRef2)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), identityRoleRef2ForRole2)
	createdIdentityRoles2 = append(createdIdentityRoles2, *identityRoleRef2ForRole2)

	// role 2
	identityRoleRef1, err := testsupport.CreateTestIdentityRole(s.Ctx, s.DB, *resourceRef, *roleRef)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), identityRoleRef1)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef1)

	identityRoleRef2, err := testsupport.CreateTestIdentityRole(s.Ctx, s.DB, *resourceRef, *roleRef)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), identityRoleRef1)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef2)

	// Validate

	identityRoles, err := s.roleManagementService.ListByResourceAndRoleName(s.Ctx, identityRoleRef1.Resource.ResourceID, roleRef.Name)
	require.NoError(t, err)
	require.Len(t, identityRoles, 2)
	require.Equal(t, true, s.checkExists(*identityRoleRef1, identityRoles, false))
	require.Equal(t, true, s.checkExists(*identityRoleRef2, identityRoles, false))

	identityRoles, err = s.roleManagementService.ListByResourceAndRoleName(s.Ctx, identityRoleRef2ForRole2.Resource.ResourceID, roleRef2.Name)
	require.NoError(t, err)
	require.Len(t, identityRoles, 2)
	require.Equal(t, true, s.checkExists(*identityRoleRef1ForRole2, identityRoles, false))
	require.Equal(t, true, s.checkExists(*identityRoleRef2ForRole2, identityRoles, false))

	identityRoles, err = s.roleManagementService.ListByResourceAndRoleName(s.Ctx, identityRoleRef2ForRole2.Resource.ResourceID, uuid.NewV4().String())
	require.NoError(t, err)
	require.Len(t, identityRoles, 0)

	identityRoles, err = s.roleManagementService.ListByResourceAndRoleName(s.Ctx, uuid.NewV4().String(), uuid.NewV4().String())
	require.Error(t, err)
	require.Len(t, identityRoles, 0)
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
