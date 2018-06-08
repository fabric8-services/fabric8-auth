package controller_test

import (
	"github.com/fabric8-services/fabric8-auth/authorization"
	"testing"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestResourceRolesRest struct {
	gormtestsupport.DBTestSuite
}

func (s *TestResourceRolesRest) SetupSuite() {
	s.DBTestSuite.SetupSuite()
}

func (rest *TestResourceRolesRest) SecuredControllerWithIdentity(identity account.Identity) (*goa.Service, *ResourceRolesController) {
	svc := testsupport.ServiceAsUser("Resource-roles-Service", identity)
	return svc, NewResourceRolesController(svc, rest.Application)
}

func (rest *TestResourceRolesRest) SecuredControllerWithIncompleteIdentity(identity account.Identity) (*goa.Service, *ResourceRolesController) {
	svc := testsupport.ServiceAsUserWithIncompleteClaims("Resource-roles-Service", identity)
	return svc, NewResourceRolesController(svc, rest.Application)
}

func (rest *TestResourceRolesRest) UnSecuredController() (*goa.Service, *ResourceRolesController) {
	svc := testsupport.UnsecuredService("Resource-roles-Service")
	return svc, NewResourceRolesController(svc, rest.Application)
}

func TestRunResourceRolesRest(t *testing.T) {
	suite.Run(t, &TestResourceRolesRest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestResourceRolesRest) TestListAssignedRolesOK() {

	// Create a role for the inbuilt resource type
	// Create a resource of the inbuilt resource type
	// Create two assignments for that role.

	resourceOwner := testsupport.TestIdentity2
	err := testsupport.CreateTestIdentityAndUserInDB(rest.DB, &resourceOwner)
	require.NoError(rest.T(), err)

	areaResourceType, err := rest.Application.ResourceTypeRepository().Lookup(rest.Ctx, "openshift.io/resource/area")
	require.NoError(rest.T(), err)

	resourceRef, err := testsupport.CreateTestResource(rest.Ctx, rest.DB, *areaResourceType, "SpaceR", nil)
	require.NoError(rest.T(), err)

	// assigned roles for this should not be returned.
	resourceRefUnrelated, err := testsupport.CreateTestResource(rest.Ctx, rest.DB, *areaResourceType, "SpaceRUnrelated", nil)
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

	// this assigned role should not be returned when we later
	// on list the assigned roles.
	identityRoleRefUnrelated, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *resourceRefUnrelated, *roleRef)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), identityRoleRefUnrelated)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRefUnrelated)

	svc, ctrl := rest.SecuredControllerWithIdentity(testsupport.TestIdentity)
	_, returnedIdentityRoles := test.ListAssignedResourceRolesOK(rest.T(), rest.Ctx, svc, ctrl, resourceRef.ResourceID)
	require.Len(rest.T(), returnedIdentityRoles.Data, 2)
	require.True(rest.T(), rest.checkExists(*identityRoleRef, returnedIdentityRoles, false))
	require.True(rest.T(), rest.checkExists(*identityRoleRef2, returnedIdentityRoles, false))
}

func (rest *TestResourceRolesRest) TestListAssignedRolesNotFound() {
	svc, ctrl := rest.SecuredControllerWithIdentity(testsupport.TestIdentity)
	test.ListAssignedResourceRolesNotFound(rest.T(), rest.Ctx, svc, ctrl, uuid.NewV4().String())
}

func (rest *TestResourceRolesRest) TestListAssignedRolesByRoleNameNotFound() {
	svc, ctrl := rest.SecuredControllerWithIdentity(testsupport.TestIdentity)
	test.ListAssignedByRoleNameResourceRolesNotFound(rest.T(), rest.Ctx, svc, ctrl, uuid.NewV4().String(), uuid.NewV4().String())
}

func (rest *TestResourceRolesRest) TestListAssignedRolesFromInheritedOK() {

	// Create a resource of the inbuilt resource type
	// Create a child resource of the above resource
	// Create a role for that resource type
	// Create two assignments for that role
	// Validate for 'Inherited' field's response

	resourceOwner := testsupport.TestIdentity2
	err := testsupport.CreateTestIdentityAndUserInDB(rest.DB, &resourceOwner)
	require.NoError(rest.T(), err)

	areaResourceType, err := rest.Application.ResourceTypeRepository().Lookup(rest.Ctx, "openshift.io/resource/area")
	require.NoError(rest.T(), err)

	parentResourceRef, err := testsupport.CreateTestResource(rest.Ctx, rest.DB, *areaResourceType, "SpaceR", nil)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), parentResourceRef)

	resourceRef, err := testsupport.CreateTestResource(rest.Ctx, rest.DB, *areaResourceType, "SpaceH", &parentResourceRef.ResourceID)
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

func (rest *TestResourceRolesRest) TestListAssignedRolesByRoleNameFromInheritedOK() {

	// Create a resource of the inbuilt resource type
	// Create a child resource of the above resource
	// Create a role for that resource type
	// Create two assignments for that role
	// Validate for 'Inherited' field's response

	resourceOwner := testsupport.TestIdentity2
	err := testsupport.CreateTestIdentityAndUserInDB(rest.DB, &resourceOwner)
	require.NoError(rest.T(), err)

	areaResourceType, err := rest.Application.ResourceTypeRepository().Lookup(rest.Ctx, "openshift.io/resource/area")
	require.NoError(rest.T(), err)

	parentResourceRef, err := testsupport.CreateTestResource(rest.Ctx, rest.DB, *areaResourceType, "SpaceR", nil)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), parentResourceRef)

	resourceRef, err := testsupport.CreateTestResource(rest.Ctx, rest.DB, *areaResourceType, "SpaceH", &parentResourceRef.ResourceID)
	require.NoError(rest.T(), err)

	roleRef, err := testsupport.CreateTestRole(rest.Ctx, rest.DB, *areaResourceType, "collab")
	require.NoError(rest.T(), err)

	roleRefGroup2, err := testsupport.CreateTestRole(rest.Ctx, rest.DB, *areaResourceType, "collab-x")
	require.NoError(rest.T(), err)

	var createdIdentityRoles []role.IdentityRole
	var createdIdentityRolesGroup2 []role.IdentityRole

	identityRoleRef, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *resourceRef, *roleRef)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), identityRoleRef)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef)

	identityRoleRef2, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *resourceRef, *roleRef)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), identityRoleRef2)
	createdIdentityRoles = append(createdIdentityRoles, *identityRoleRef2)

	// second role

	identityRoleRef1InGroup2, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *resourceRef, *roleRefGroup2)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), identityRoleRef1InGroup2)
	createdIdentityRolesGroup2 = append(createdIdentityRolesGroup2, *identityRoleRef1InGroup2)

	identityRoleRef2InGroup2, err := testsupport.CreateTestIdentityRole(rest.Ctx, rest.DB, *resourceRef, *roleRefGroup2)
	require.NoError(rest.T(), err)
	require.NotNil(rest.T(), identityRoleRef2InGroup2)
	createdIdentityRolesGroup2 = append(createdIdentityRolesGroup2, *identityRoleRef2InGroup2)

	svc, ctrl := rest.SecuredControllerWithIdentity(testsupport.TestIdentity)
	_, returnedIdentityRoles := test.ListAssignedByRoleNameResourceRolesOK(rest.T(), rest.Ctx, svc, ctrl, resourceRef.ResourceID, roleRef.Name)
	require.Len(rest.T(), returnedIdentityRoles.Data, 2)
	require.True(rest.T(), rest.checkExists(*identityRoleRef, returnedIdentityRoles, true))
	require.True(rest.T(), rest.checkExists(*identityRoleRef2, returnedIdentityRoles, true))

	_, returnedIdentityRoles = test.ListAssignedByRoleNameResourceRolesOK(rest.T(), rest.Ctx, svc, ctrl, resourceRef.ResourceID, roleRefGroup2.Name)
	require.Len(rest.T(), returnedIdentityRoles.Data, 2)
	require.True(rest.T(), rest.checkExists(*identityRoleRef1InGroup2, returnedIdentityRoles, true))
	require.True(rest.T(), rest.checkExists(*identityRoleRef2InGroup2, returnedIdentityRoles, true))

	// include these as a side-test
	test.ListAssignedByRoleNameResourceRolesNotFound(rest.T(), rest.Ctx, svc, ctrl, resourceRef.ResourceID, uuid.NewV4().String())
}

func (rest *TestResourceRolesRest) TestAssignRoleOK() {

	g := rest.DBTestSuite.NewTestGraph()
	res := g.CreateSpace()

	var identitiesToBeAssigned []string
	for i := 0; i <= 10; i++ {
		testUser := g.CreateUser()
		res.AddViewer(testUser)
		identitiesToBeAssigned = append(identitiesToBeAssigned, testUser.Identity().ID.String())
	}

	roleAssignment := &app.AssignRoleData{Role: authorization.SpaceContributorRole, Ids: identitiesToBeAssigned}
	assignments := []*app.AssignRoleData{roleAssignment}

	// Create a user who has the privileges to assign roles
	adminUser := g.CreateUser("adminuser")
	res.AddAdmin(adminUser)

	svc, ctrl := rest.SecuredControllerWithIdentity(*adminUser.Identity())
	payload := &app.AssignRoleResourceRolesPayload{
		Data: assignments,
	}

	test.AssignRoleResourceRolesNoContent(rest.T(), svc.Context, svc, ctrl, res.SpaceID(), payload)
}

func (rest *TestResourceRolesRest) TestAssignRoleConflict() {

	g := rest.DBTestSuite.NewTestGraph()
	res := g.CreateSpace()

	testUser := g.CreateUser()
	res.AddViewer(testUser)

	// Create a user who has the privileges to assign roles
	adminUser := g.CreateUser("adminuser")
	res.AddAdmin(adminUser)

	svc, ctrl := rest.SecuredControllerWithIdentity(*adminUser.Identity())
	payload := &app.AssignRoleResourceRolesPayload{
		Data: []*app.AssignRoleData{
			{
				Role: authorization.SpaceContributorRole,
				Ids:  []string{testUser.Identity().ID.String()},
			},
		},
	}

	test.AssignRoleResourceRolesNoContent(rest.T(), svc.Context, svc, ctrl, res.SpaceID(), payload)
	test.AssignRoleResourceRolesConflict(rest.T(), svc.Context, svc, ctrl, res.SpaceID(), payload)
}

func (rest *TestResourceRolesRest) TestAssignRoleUnauthorized() {
	svc, ctrl := rest.UnSecuredController()
	payload := app.AssignRoleResourceRolesPayload{
		Data: []*app.AssignRoleData{},
	}
	test.AssignRoleResourceRolesUnauthorized(rest.T(), rest.Ctx, svc, ctrl, uuid.NewV4().String(), &payload)
}

func (rest *TestResourceRolesRest) TestAssignRoleBadRequestUserNotInSpace() {
	g := rest.DBTestSuite.NewTestGraph()
	res := g.CreateSpace()

	var identitiesToBeAssigned []*app.AssignRoleData

	// some already have roles assigned
	for i := 0; i <= 2; i++ {
		testUser := g.CreateUser()
		identitiesToBeAssigned = append(identitiesToBeAssigned, &app.AssignRoleData{Role: authorization.SpaceContributorRole, Ids: []string{testUser.Identity().ID.String()}})
		res.AddViewer(testUser)
	}

	// while others don't have any role assigned.
	for i := 0; i <= 2; i++ {
		testUser := g.CreateUser()
		identitiesToBeAssigned = append(identitiesToBeAssigned, &app.AssignRoleData{Role: authorization.SpaceContributorRole, Ids: []string{testUser.Identity().ID.String()}})
	}

	// Create a user who has the privileges to assign roles
	adminUser := g.CreateUser("adminuser")
	res.AddAdmin(adminUser)

	svc, ctrl := rest.SecuredControllerWithIdentity(*adminUser.Identity())
	payload := &app.AssignRoleResourceRolesPayload{
		Data: identitiesToBeAssigned,
	}

	test.AssignRoleResourceRolesBadRequest(rest.T(), svc.Context, svc, ctrl, res.SpaceID(), payload)
}

func (rest *TestResourceRolesRest) TestAssignRoleForbiddenNotAllowedToAssignRoles() {
	g := rest.DBTestSuite.NewTestGraph()
	res := g.CreateSpace(g.ID("somespacename"))

	var identitiesToBeAssigned []*app.AssignRoleData
	for i := 0; i <= 2; i++ {
		testUser := g.CreateUser()
		res.AddViewer(testUser)
		identitiesToBeAssigned = append(identitiesToBeAssigned, &app.AssignRoleData{Role: authorization.SpaceContributorRole, Ids: []string{testUser.Identity().ID.String()}})
	}

	// Create a user who has the privileges to assign roles
	adminUser := g.CreateUser("adminuser")
	res.AddContributor(adminUser) //not really an admin

	svc, ctrl := rest.SecuredControllerWithIdentity(*adminUser.Identity())
	payload := &app.AssignRoleResourceRolesPayload{
		Data: identitiesToBeAssigned,
	}

	test.AssignRoleResourceRolesForbidden(rest.T(), svc.Context, svc, ctrl, res.SpaceID(), payload)
}

func (rest *TestResourceRolesRest) TestAssignRoleWithInvalidIdentityIDBadRequest() {
	g := rest.DBTestSuite.NewTestGraph()
	res := g.CreateSpace(g.ID("somespacename"))

	var identitiesToBeAssigned []*app.AssignRoleData
	for i := 0; i <= 2; i++ {
		identitiesToBeAssigned = append(identitiesToBeAssigned, &app.AssignRoleData{Role: authorization.SpaceContributorRole, Ids: []string{uuid.NewV4().String() + "#$%"}})
	}

	// Create a user who has the privileges to assign roles
	adminUser := g.CreateUser("adminuser")
	res.AddAdmin(adminUser)

	svc, ctrl := rest.SecuredControllerWithIdentity(*adminUser.Identity())
	payload := &app.AssignRoleResourceRolesPayload{
		Data: identitiesToBeAssigned,
	}

	test.AssignRoleResourceRolesBadRequest(rest.T(), svc.Context, svc, ctrl, res.SpaceID(), payload)
}

func (rest *TestResourceRolesRest) TestAssignRoleWithIncompleteTokenClaims() {
	g := rest.DBTestSuite.NewTestGraph()
	res := g.CreateSpace(g.ID("somespacename"))

	var identitiesToBeAssigned []*app.AssignRoleData
	for i := 0; i <= 2; i++ {
		identitiesToBeAssigned = append(identitiesToBeAssigned, &app.AssignRoleData{Role: authorization.SpaceContributorRole, Ids: []string{uuid.NewV4().String() + "#$%"}})
	}
	adminUser := g.CreateUser("adminuser")
	res.AddContributor(adminUser) //not really an admin

	svc, ctrl := rest.SecuredControllerWithIncompleteIdentity(*adminUser.Identity())
	payload := &app.AssignRoleResourceRolesPayload{
		Data: identitiesToBeAssigned,
	}

	test.AssignRoleResourceRolesUnauthorized(rest.T(), svc.Context, svc, ctrl, res.SpaceID(), payload)
}

func (rest *TestResourceRolesRest) checkExists(createdRole role.IdentityRole, pool *app.Identityroles, isInherited bool) bool {
	for _, retrievedRole := range pool.Data {
		if retrievedRole.AssigneeID == createdRole.IdentityID.String() {
			rest.compare(createdRole, *retrievedRole, isInherited)
			return true
		}
	}
	return false
}

func (rest *TestResourceRolesRest) compare(createdRole role.IdentityRole, retrievedRole app.IdentityRolesData, isInherited bool) bool {
	require.Equal(rest.T(), createdRole.IdentityID.String(), retrievedRole.AssigneeID)
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
