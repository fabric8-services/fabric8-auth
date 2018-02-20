package authorization_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/authorization/models"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/goadesign/goa/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type roleAssignmentServiceBlackboxTest struct {
	gormtestsupport.DBTestSuite
	assignmentService authorization.RoleAssignmentService
}

func TestRunRoleAssignmentServiceBlackboxTest(t *testing.T) {
	suite.Run(t, &roleAssignmentServiceBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *roleAssignmentServiceBlackboxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	modelService := models.NewRoleAssignmentModelService(s.DB, s.Application)
	s.assignmentService = authorization.NewRoleAssignmentService(modelService, s.Application)
}
func (s *roleAssignmentServiceBlackboxTest) TestGetIdentityRoleByResource() {
	t := s.T()
	identityRole, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRole)

	identityRoles, err := s.assignmentService.ListByResource(s.Ctx, identityRole.Resource.ResourceID)
	require.NoError(t, err)
	require.Equal(t, true, len(identityRoles) == 1)
	require.Equal(t, identityRole.Resource.ResourceID, identityRoles[0].Resource.ResourceID)
}

func (s *roleAssignmentServiceBlackboxTest) TestGetMultipleIdentityRoleByResourceInherited() {

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

	var createdIdentityRoles []role.IdentityRole

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

	identityRoles, err := s.assignmentService.ListByResource(s.Ctx, identityRoleRef1.Resource.ResourceID)
	require.NoError(t, err)
	require.Len(t, identityRoles, 3)
	require.Equal(t, true, s.checkExists(*identityRoleRef1, identityRoles, true))
	require.Equal(t, true, s.checkExists(*identityRoleRef2, identityRoles, true))
	require.Equal(t, true, s.checkExists(*identityRoleRefUnrelated, identityRoles, false))

}

func (s *roleAssignmentServiceBlackboxTest) TestGetIdentityRolesOfParentResource() {

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

	var createdIdentityRoles []role.IdentityRole

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

	identityRoles, err := s.assignmentService.ListByResource(s.Ctx, identityRoleRefUnrelated.Resource.ResourceID)
	require.NoError(t, err)
	require.Len(t, identityRoles, 1)
	require.Equal(t, true, s.checkExists(*identityRoleRefUnrelated, identityRoles, false))

}

func (s *roleAssignmentServiceBlackboxTest) TestGetMultipleIdentityRoleByResourceNotInherited() {
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

	var createdIdentityRoles []role.IdentityRole

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

	identityRoles, err := s.assignmentService.ListByResource(s.Ctx, identityRoleRef1.Resource.ResourceID)
	require.NoError(t, err)
	require.Len(t, identityRoles, 2)
	require.Equal(t, true, s.checkExists(*identityRoleRef1, identityRoles, false))
	require.Equal(t, true, s.checkExists(*identityRoleRef2, identityRoles, false))

}

func (s *roleAssignmentServiceBlackboxTest) TestGetIdentityRoleByResourceNotFound() {
	t := s.T()
	identityRole, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRole)

	identityRoles, err := s.assignmentService.ListByResource(s.Ctx, uuid.NewV4().String())
	require.Error(t, errors.NotFoundError{})
	require.Equal(t, 0, len(identityRoles))
}

func (s *roleAssignmentServiceBlackboxTest) checkExists(createdRole role.IdentityRole, pool []role.IdentityRole, isInherited bool) bool {
	for _, retrievedRole := range pool {
		if retrievedRole.IdentityRoleID.String() == createdRole.IdentityRoleID.String() {
			s.compare(createdRole, retrievedRole, isInherited)
			return true
		}
	}
	return false
}

func (s *roleAssignmentServiceBlackboxTest) compare(createdRole role.IdentityRole, retrievedRole role.IdentityRole, isInherited bool) bool {
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
