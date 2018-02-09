package controller_test

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"

	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"

	"github.com/goadesign/goa"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestResourceRolesRest struct {
	gormtestsupport.DBTestSuite
	rolesRepository         role.RoleRepository
	resourceRepository      resource.ResourceRepository
	identityRolesRepository role.IdentityRoleRepository
	resourceTypeRepository  resource.ResourceTypeRepository
}

func (s *TestResourceRolesRest) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	var err error

	s.DB = s.DB.Debug()

	s.identityRolesRepository = role.NewIdentityRoleRepository(s.DB)
	s.resourceRepository = resource.NewResourceRepository(s.DB)
	s.rolesRepository = role.NewRoleRepository(s.DB)
	s.resourceTypeRepository = resource.NewResourceTypeRepository(s.DB)

	require.Nil(s.T(), err)
}

func (rest *TestResourceRolesRest) SecuredControllerWithIdentity(identity account.Identity) (*goa.Service, *ResourceRolesController) {
	svc := testsupport.ServiceAsUser("Resource-roles-Service", identity)
	return svc, NewResourceRolesController(svc, testtoken.TokenManager, rest.Application)
}

func TestRunResourceRolesRest(t *testing.T) {
	suite.Run(t, &TestResourceRolesRest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestResourceRolesRest) SecuredController(identity account.Identity) (*goa.Service, *ResourceController) {
	svc := testsupport.ServiceAsUser("Resource-Service", identity)
	return svc, NewResourceController(svc, rest.Application)
}

func (rest *TestResourceRolesRest) TestListAssignedRolesOK() {

	// Create a resource of the inbuilt resource type
	// Create a role for that resource type
	// Create two assignments for that role.

	resourceOwner := testsupport.TestIdentity2
	err := testsupport.CreateTestIdentityAndUserInDB(rest.DB, &resourceOwner)
	require.NoError(rest.T(), err)

	areaResourceType, err := rest.resourceTypeRepository.Lookup(rest.Ctx, "openshift.io/resource/area")
	require.NoError(rest.T(), err)

	resourceRef, err := testsupport.CreateTestResource(rest.Ctx, rest.DB, *areaResourceType, "SpaceR")
	require.NoError(rest.T(), err)

	roleRef, err := testsupport.CreateTestRole(rest.Ctx, rest.DB, *areaResourceType, "collab")
	require.NoError(rest.T(), err)

	var createdIdentityRoles []role.IdentityRole

	identityRoleRef, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *resourceRef, *roleRef)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), identityRoleRef)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef)

	identityRoleRef2, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *resourceRef, *roleRef)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), identityRoleRef2)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef2)

	svc, ctrl := rest.SecuredControllerWithIdentity(testsupport.TestIdentity)
	_, returnedIdentityRoles := test.ListAssignedResourceRolesOK(rest.T(), rest.Ctx, svc, ctrl, resourceRef.ResourceID)
	require.Len(rest.T(), returnedIdentityRoles.Data, 2)
	require.True(rest.T(), rest.checkExists(*identityRoleRef, returnedIdentityRoles, false))
	require.True(rest.T(), rest.checkExists(*identityRoleRef2, returnedIdentityRoles, false))
}

func (rest *TestResourceRolesRest) TestListAssignedRolesFromInheritedOK() {

	// Create a resource of the inbuilt resource type
	// Create a child resource of the above resource
	// Create a role for that resource type
	// Create two assignments for that role.
	// Validate for 'Inherited' field's response.

	resourceOwner := testsupport.TestIdentity2
	err := testsupport.CreateTestIdentityAndUserInDB(rest.DB, &resourceOwner)
	require.NoError(rest.T(), err)

	areaResourceType, err := rest.resourceTypeRepository.Lookup(rest.Ctx, "openshift.io/resource/area")
	require.NoError(rest.T(), err)

	parentResourceRef, err := testsupport.CreateTestResource(rest.Ctx, rest.DB, *areaResourceType, "SpaceR")
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), parentResourceRef)

	resourceRef, err := testsupport.CreateInheritedTestResource(rest.Ctx, rest.DB, *areaResourceType, "SpaceH", *parentResourceRef)
	require.NoError(rest.T(), err)

	roleRef, err := testsupport.CreateTestRole(rest.Ctx, rest.DB, *areaResourceType, "collab")
	require.NoError(rest.T(), err)

	var createdIdentityRoles []role.IdentityRole

	identityRoleRef, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *resourceRef, *roleRef)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), identityRoleRef)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef)

	identityRoleRef2, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *resourceRef, *roleRef)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), identityRoleRef2)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef2)

	svc, ctrl := rest.SecuredControllerWithIdentity(testsupport.TestIdentity)
	_, returnedIdentityRoles := test.ListAssignedResourceRolesOK(rest.T(), rest.Ctx, svc, ctrl, resourceRef.ResourceID)
	require.Len(rest.T(), returnedIdentityRoles.Data, 2)
	require.True(rest.T(), rest.checkExists(*identityRoleRef, returnedIdentityRoles, true))
	require.True(rest.T(), rest.checkExists(*identityRoleRef2, returnedIdentityRoles, true))
}

func (rest *TestResourceRolesRest) checkExists(createdRole role.IdentityRole, pool *app.Identityroles, isInherited bool) bool {
	for _, retrievedRole := range pool.Data {
		if retrievedRole.Identifier == createdRole.IdentityRoleID.String() {
			rest.compare(createdRole, *retrievedRole, isInherited)
			return true
		}
	}
	return false
}

func (rest *TestResourceRolesRest) compare(createdRole role.IdentityRole, retrievedRole app.IdentityRolesData, isInherited bool) bool {
	require.Equal(rest.T(), createdRole.IdentityRoleID.String(), retrievedRole.Identifier)
	require.Equal(rest.T(), createdRole.IdentityID.String(), retrievedRole.AssigneeID)
	require.Equal(rest.T(), createdRole.RoleID.String(), retrievedRole.RoleID)
	require.Equal(rest.T(), createdRole.Role.Name, retrievedRole.RoleName)
	require.Equal(rest.T(), "user", retrievedRole.AssigneeType)
	if isInherited {
		require.True(rest.T(), retrievedRole.Inherited)
		require.NotNil(rest.T(), createdRole.Resource.ParentResourceID)
		require.Equal(rest.T(), *createdRole.Resource.ParentResourceID, *createdRole.Resource.ParentResourceID)
	} else {
		require.False(rest.T(), retrievedRole.Inherited)
	}
	return true
}