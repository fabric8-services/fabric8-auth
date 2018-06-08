package controller_test

import (
	"testing"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/authorization"
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

func (rest *TestResourceRolesRest) SecuredControllerWithServiceAccount(serviceAccountName string) (*goa.Service, *ResourceRolesController) {
	identity, err := testsupport.CreateTestIdentityAndUser(rest.DB, serviceAccountName, "KC")
	require.NoError(rest.T(), err)

	svc := testsupport.ServiceAsServiceAccountUser(serviceAccountName, identity)
	return svc, NewResourceRolesController(svc, rest.Application)
}

func TestRunResourceRolesRest(t *testing.T) {
	suite.Run(t, &TestResourceRolesRest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestResourceRolesRest) TestListAssignedRolesOK() {
	admin := rest.Graph.CreateUser()
	viewer := rest.Graph.CreateUser()
	space := rest.Graph.CreateSpace().AddAdmin(admin).AddViewer(viewer)

	// noise
	rest.Graph.CreateSpace().AddViewer(rest.Graph.CreateUser())

	// Check available roles
	svc, ctrl := rest.SecuredControllerWithIdentity(*viewer.Identity())
	_, returnedIdentityRoles := test.ListAssignedResourceRolesOK(rest.T(), svc.Context, svc, ctrl, space.SpaceID())
	require.Len(rest.T(), returnedIdentityRoles.Data, 2)
	rest.checkExists([]uuid.UUID{admin.IdentityID(), viewer.IdentityID()}, []string{"admin", "viewer"}, returnedIdentityRoles)
}

func (rest *TestResourceRolesRest) TestListAssignedRolesByRoleNameOK() {
	admin := rest.Graph.CreateUser()
	viewer := rest.Graph.CreateUser()
	space := rest.Graph.CreateSpace().AddAdmin(admin).AddViewer(viewer)

	// noise
	rest.Graph.CreateSpace().AddAdmin(rest.Graph.CreateUser())

	// Check available roles
	svc, ctrl := rest.SecuredControllerWithIdentity(*viewer.Identity())
	_, returnedIdentityRoles := test.ListAssignedByRoleNameResourceRolesOK(rest.T(), svc.Context, svc, ctrl, space.SpaceID(), "admin")
	require.Len(rest.T(), returnedIdentityRoles.Data, 1)
	rest.checkExists([]uuid.UUID{admin.IdentityID()}, []string{"admin"}, returnedIdentityRoles)
}

func (rest *TestResourceRolesRest) TestListAssignedRolesUnauthorized() {
	svc, ctrl := rest.SecuredControllerWithIdentity(*rest.Graph.CreateUser().Identity())
	space := rest.Graph.CreateSpace()
	test.ListAssignedResourceRolesForbidden(rest.T(), svc.Context, svc, ctrl, space.SpaceID())
}

func (rest *TestResourceRolesRest) TestListAssignedRolesNotFound() {
	svc, ctrl := rest.SecuredControllerWithIdentity(*rest.Graph.CreateUser().Identity())
	test.ListAssignedResourceRolesNotFound(rest.T(), svc.Context, svc, ctrl, uuid.NewV4().String())
}

func (rest *TestResourceRolesRest) TestListAssignedRolesByRoleNameUnauthorized() {
	svc, ctrl := rest.SecuredControllerWithIdentity(*rest.Graph.CreateUser().Identity())
	space := rest.Graph.CreateSpace()
	test.ListAssignedByRoleNameResourceRolesForbidden(rest.T(), svc.Context, svc, ctrl, space.SpaceID(), authorization.SpaceViewerRole)
}

func (rest *TestResourceRolesRest) TestListAssignedRolesByRoleNameNotFound() {
	svc, ctrl := rest.SecuredControllerWithIdentity(*rest.Graph.CreateUser().Identity())
	test.ListAssignedByRoleNameResourceRolesNotFound(rest.T(), svc.Context, svc, ctrl, uuid.NewV4().String(), authorization.SpaceViewerRole)
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

func (rest *TestResourceRolesRest) TestAssignRoleUserNotInSpaceOK() {
	g := rest.DBTestSuite.NewTestGraph()
	res := g.CreateSpace()

	var identitiesToBeAssigned []*app.AssignRoleData

	// don't have any role assigned.
	for i := 0; i <= 2; i++ {
		testUser := g.CreateUser()
		identitiesToBeAssigned = append(identitiesToBeAssigned, &app.AssignRoleData{Role: authorization.SpaceContributorRole, Ids: []string{testUser.Identity().ID.String()}})
	}

	svc, ctrl := rest.SecuredControllerWithServiceAccount("space-migration")
	payload := &app.AssignRoleResourceRolesPayload{
		Data: identitiesToBeAssigned,
	}

	test.AssignRoleResourceRolesNoContent(rest.T(), svc.Context, svc, ctrl, res.SpaceID(), payload)
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

func (rest *TestResourceRolesRest) checkExists(identities []uuid.UUID, roleNames []string, pool *app.Identityroles) {
	for _, retrievedRole := range pool.Data {
		var foundUser bool
		for i, idn := range identities {
			foundUser = idn.String() == retrievedRole.AssigneeID && retrievedRole.RoleName == roleNames[i]
			if foundUser {
				break
			}
		}
		require.True(rest.T(), foundUser)
	}
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
