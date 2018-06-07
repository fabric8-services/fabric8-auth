package controller_test

import (
	"context"
	"fmt"
	"testing"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/authorization"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestSpaceREST struct {
	gormtestsupport.DBTestSuite
	resourceID      string
	permissionID    string
	policyID        string
	resourceService service.ResourceService
}

func TestRunSpaceREST(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &TestSpaceREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestSpaceREST) SetupTest() {
	rest.DBTestSuite.SetupTest()
	rest.resourceID = uuid.NewV4().String()
	rest.permissionID = uuid.NewV4().String()
	rest.policyID = uuid.NewV4().String()
	rest.resourceService = rest.Application.ResourceService()
}

func (rest *TestSpaceREST) SecuredController() (*goa.Service, *SpaceController, account.Identity) {
	identity, err := testsupport.CreateTestIdentityAndUser(rest.DB, uuid.NewV4().String(), "KC")
	require.NoError(rest.T(), err)

	svc := testsupport.ServiceAsUser("Space-Service", identity)
	return svc, NewSpaceController(svc, rest.Application, rest.Configuration, &DummyResourceManager{
		ResourceID:   &rest.resourceID,
		PermissionID: &rest.permissionID,
		PolicyID:     &rest.policyID,
	}), identity
}

func (rest *TestSpaceREST) SecuredControllerWithServiceAccount(serviceAccountName string) (*goa.Service, *SpaceController, account.Identity) {
	identity, err := testsupport.CreateTestIdentityAndUser(rest.DB, serviceAccountName, "KC")
	require.NoError(rest.T(), err)

	svc := testsupport.ServiceAsServiceAccountUser(serviceAccountName, identity)
	return svc, NewSpaceController(svc, rest.Application, rest.Configuration, &DummyResourceManager{
		ResourceID:   &rest.resourceID,
		PermissionID: &rest.permissionID,
		PolicyID:     &rest.policyID,
	}), identity
}

func (rest *TestSpaceREST) SecuredControllerForIdentity(identity account.Identity) (*goa.Service, *SpaceController) {
	svc := testsupport.ServiceAsUser("Space-Service", identity)
	return svc, NewSpaceController(svc, rest.Application, rest.Configuration, nil)
}

func (rest *TestSpaceREST) UnSecuredController() (*goa.Service, *SpaceController) {
	svc := goa.New("Space-Service")
	return svc, NewSpaceController(svc, rest.Application, rest.Configuration, &DummyResourceManager{
		ResourceID:   &rest.resourceID,
		PermissionID: &rest.permissionID,
		PolicyID:     &rest.policyID,
	})
}

func (rest *TestSpaceREST) UnSecuredControllerWithDeprovisionedIdentity() (*goa.Service, *SpaceController) {
	identity, err := testsupport.CreateDeprovisionedTestIdentityAndUser(rest.DB, uuid.NewV4().String())
	require.NoError(rest.T(), err)

	svc := testsupport.ServiceAsUser("Space-Service", identity)
	return svc, NewSpaceController(svc, rest.Application, rest.Configuration, &DummyResourceManager{
		ResourceID:   &rest.resourceID,
		PermissionID: &rest.permissionID,
		PolicyID:     &rest.policyID,
	})
}

func (rest *TestSpaceREST) TestFailCreateSpaceUnauthorized() {
	// given
	svc, ctrl := rest.UnSecuredController()
	// when/then
	test.CreateSpaceUnauthorized(rest.T(), svc.Context, svc, ctrl, uuid.NewV4(), nil)
}

func (rest *TestSpaceREST) TestCreateSpaceUnauthorizedDeprovisionedUser() {
	// given
	svc, ctrl := rest.UnSecuredControllerWithDeprovisionedIdentity()
	// when/then
	test.CreateSpaceUnauthorized(rest.T(), svc.Context, svc, ctrl, uuid.NewV4(), nil)
}

func (rest *TestSpaceREST) TestCreateSpaceWithServiceAccountOK() {
	svc, ctrl, creator := rest.SecuredControllerWithServiceAccount("space-migration")
	spaceID := uuid.NewV4()

	_, createdSpaceResource := test.CreateSpaceOK(rest.T(), svc.Context, svc, ctrl, spaceID, &creator.ID)
	assert.Equal(rest.T(), spaceID.String(), createdSpaceResource.Data.ResourceID)
	assert.Equal(rest.T(), uuid.Nil.String(), createdSpaceResource.Data.PermissionID)
	assert.Equal(rest.T(), uuid.Nil.String(), createdSpaceResource.Data.PolicyID)

	// Check if the corresponding authZ resource has been created
	resource, err := rest.resourceService.Read(context.Background(), spaceID.String())
	require.NoError(rest.T(), err)
	assert.Equal(rest.T(), spaceID.String(), *resource.ResourceID)
	assert.Equal(rest.T(), authorization.ResourceTypeSpace, *resource.Type)

	// Check the admin role has been assigned to the space creator
	assignedRoles, err := rest.Application.RoleManagementService().ListByResource(context.Background(), creator.ID, spaceID.String())
	require.NoError(rest.T(), err)
	require.Len(rest.T(), assignedRoles, 1)
	assert.Equal(rest.T(), creator.ID, assignedRoles[0].Identity.ID)
	assert.Equal(rest.T(), authorization.SpaceAdminRole, assignedRoles[0].Role.Name)
}

func (rest *TestSpaceREST) TestCreateSpaceOK() {
	svc, ctrl, creator := rest.SecuredController()
	spaceID := uuid.NewV4()

	_, created := test.CreateSpaceOK(rest.T(), svc.Context, svc, ctrl, spaceID, nil)
	require.NotNil(rest.T(), created.Data)
	assert.Equal(rest.T(), rest.resourceID, created.Data.ResourceID)
	assert.Equal(rest.T(), rest.permissionID, created.Data.PermissionID)
	assert.Equal(rest.T(), rest.policyID, created.Data.PolicyID)

	// Check if the corresponding authZ resource has been created
	resource, err := rest.resourceService.Read(context.Background(), spaceID.String())
	require.NoError(rest.T(), err)
	assert.Equal(rest.T(), spaceID.String(), *resource.ResourceID)
	assert.Equal(rest.T(), authorization.ResourceTypeSpace, *resource.Type)

	// Check the admin role has been assigned to the space creator
	assignedRoles, err := rest.Application.RoleManagementService().ListByResource(context.Background(), creator.ID, spaceID.String())
	require.NoError(rest.T(), err)
	require.Len(rest.T(), assignedRoles, 1)
	assert.Equal(rest.T(), creator.ID, assignedRoles[0].Identity.ID)
	assert.Equal(rest.T(), authorization.SpaceAdminRole, assignedRoles[0].Role.Name)
}

func (rest *TestSpaceREST) TestKeycloakResourceCreationRollBack() {
	svc, ctrl, _ := rest.SecuredController()

	g := rest.DBTestSuite.NewTestGraph()
	space := g.CreateSpace()

	spaceID, err := uuid.FromString(space.SpaceID())
	require.NoError(rest.T(), err)

	// Should fail because the space already exists.
	test.CreateSpaceInternalServerError(rest.T(), svc.Context, svc, ctrl, spaceID, nil)

	// Check that no keycloak resource exist for this space ID
	_, err = rest.Application.SpaceResources().LoadBySpace(svc.Context, &spaceID)
	testsupport.AssertError(rest.T(), err, errors.NotFoundError{}, "space resource with space_id '%s' not found", spaceID.String())
}

func (rest *TestSpaceREST) TestFailDeleteSpaceUnauthorized() {
	// given
	svc, ctrl := rest.UnSecuredController()
	// when/then
	test.DeleteSpaceUnauthorized(rest.T(), svc.Context, svc, ctrl, uuid.NewV4())
}

func (rest *TestSpaceREST) TestDeleteSpaceUnauthorizedDeprovisionedUser() {
	// given
	svc, ctrl := rest.UnSecuredControllerWithDeprovisionedIdentity()
	// when/then
	test.DeleteSpaceUnauthorized(rest.T(), svc.Context, svc, ctrl, uuid.NewV4())
}

func (rest *TestSpaceREST) TestDeleteSpaceOK() {

	// Create a space
	svc, ctrl, _ := rest.SecuredController()
	id := uuid.NewV4()
	test.CreateSpaceOK(rest.T(), svc.Context, svc, ctrl, id, nil)

	// Check if the corresponding authZ resource has been created
	_, err := rest.resourceService.Read(context.Background(), id.String())
	require.NoError(rest.T(), err)

	// Delete the space
	test.DeleteSpaceOK(rest.T(), svc.Context, svc, ctrl, id)

	// Check if the corresponding authZ resource has been deleted
	_, err = rest.resourceService.Read(context.Background(), id.String())
	require.Error(rest.T(), err)
	require.EqualError(rest.T(), err, fmt.Sprintf("resource with id '%s' not found", id.String()))
}

func (rest *TestSpaceREST) TestDeleteOldSpaceOK() {

	// Create a space
	svc, ctrl, _ := rest.SecuredController()
	id := uuid.NewV4()
	test.CreateSpaceOK(rest.T(), svc.Context, svc, ctrl, id, nil)

	// Now let's emulate an old space which was created before we started to register resources for new spaces
	// Delete the corresponding resource for the created space
	err := rest.resourceService.Delete(context.Background(), id.String())
	require.NoError(rest.T(), err)

	// Try to delete the space. It should not fail even if the corresponding resource is not found
	test.DeleteSpaceOK(rest.T(), svc.Context, svc, ctrl, id)
}

func (rest *TestSpaceREST) TestDeleteSpaceIfUserIsNotSpaceOwnerForbidden() {
	// Create a space
	svcOwner, ctrlOwner, _ := rest.SecuredController()
	svcNotOwner, ctrlNotOwner, _ := rest.SecuredController()
	id := uuid.NewV4()
	test.CreateSpaceOK(rest.T(), svcOwner.Context, svcOwner, ctrlOwner, id, nil)

	// Try to delete
	test.DeleteSpaceForbidden(rest.T(), svcNotOwner.Context, svcNotOwner, ctrlNotOwner, id)

	// Check if the corresponding authZ resource still exists
	_, err := rest.resourceService.Read(context.Background(), id.String())
	require.NoError(rest.T(), err)
}

/*
* This test will attempt to list teams for a space
 */
func (rest *TestSpaceREST) TestListTeamOK() {
	g := rest.DBTestSuite.NewTestGraph()
	g.CreateTeam(g.ID("t1"), g.CreateSpace(g.ID("space")).
		AddAdmin(g.CreateUser(g.ID("admin"))).
		AddContributor(g.CreateUser(g.ID("contributor"))).
		AddViewer(g.CreateUser(g.ID("viewer"))))

	g.CreateTeam(g.ID("t2"), g.SpaceByID("space"))

	service, controller := rest.SecuredControllerForIdentity(*g.UserByID("admin").Identity())

	_, teams := test.ListTeamsSpaceOK(rest.T(), service.Context, service, controller, g.SpaceByID("space").SpaceID())

	require.Equal(rest.T(), 2, len(teams.Data))
	t1Found := false
	t2Found := false

	for i := range teams.Data {
		if teams.Data[i].ID == g.TeamByID("t1").TeamID().String() {
			t1Found = true
			require.Equal(rest.T(), g.TeamByID("t1").TeamName(), teams.Data[i].Name)
		} else if teams.Data[i].ID == g.TeamByID("t2").TeamID().String() {
			t2Found = true
			require.Equal(rest.T(), g.TeamByID("t2").TeamName(), teams.Data[i].Name)
		}
	}

	require.True(rest.T(), t1Found)
	require.True(rest.T(), t2Found)

	service, controller = rest.SecuredControllerForIdentity(*g.UserByID("contributor").Identity())
	_, teams = test.ListTeamsSpaceOK(rest.T(), service.Context, service, controller, g.SpaceByID("space").SpaceID())
	require.Equal(rest.T(), 2, len(teams.Data))

	service, controller = rest.SecuredControllerForIdentity(*g.UserByID("viewer").Identity())
	_, teams = test.ListTeamsSpaceOK(rest.T(), service.Context, service, controller, g.SpaceByID("space").SpaceID())
	require.Equal(rest.T(), 2, len(teams.Data))
}

func (rest *TestSpaceREST) TestListTeamUnauthorized() {
	g := rest.DBTestSuite.NewTestGraph()
	g.CreateTeam(g.ID("t1"), g.CreateSpace(g.ID("space")))
	g.CreateTeam(g.ID("t2"), g.SpaceByID("space"))

	service, controller := rest.SecuredControllerForIdentity(*g.CreateUser().Identity())
	test.ListTeamsSpaceForbidden(rest.T(), service.Context, service, controller, g.SpaceByID("space").SpaceID())

	service, controller = rest.UnSecuredController()
	test.ListTeamsSpaceUnauthorized(rest.T(), service.Context, service, controller, g.SpaceByID("space").SpaceID())
}
