package controller_test

import (
	"testing"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	authorization "github.com/fabric8-services/fabric8-auth/authorization"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestResourceREST struct {
	gormtestsupport.DBTestSuite
	testIdentity      account.Identity
	service           *goa.Service
	securedController *ResourceController
}

func (rest *TestResourceREST) SetupSuite() {
	rest.DBTestSuite.SetupSuite()
	sa := account.Identity{
		Username: "fabric8-wit",
	}
	rest.service = testsupport.ServiceAsServiceAccountUser("Resource-Service", sa)
	rest.securedController = NewResourceController(rest.service, rest.Application)
}

func TestRunResourceREST(t *testing.T) {
	suite.Run(t, &TestResourceREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestResourceREST) SecuredController(identity account.Identity) (*goa.Service, *ResourceController) {
	var err error
	rest.testIdentity, err = testsupport.CreateTestIdentity(rest.DB,
		"TestRegisterResourceCreated-"+uuid.NewV4().String(),
		"TestRegisterResourceCreated")
	require.Nil(rest.T(), err)

	svc := testsupport.ServiceAsUser("Resource-Service", identity)
	return svc, NewResourceController(svc, rest.Application)
}

/*
 * This test will attempt to register a resource with an invalid account
 */
func (rest *TestResourceREST) TestFailRegisterResourceNonServiceAccount() {
	sa := account.Identity{
		Username: "unknown-account",
	}
	service, controller := rest.SecuredController(sa)

	resourceID := ""

	payload := &app.RegisterResourcePayload{
		ParentResourceID: nil,
		ResourceID:       &resourceID,
		Type:             "openshift.io/resource/area",
	}

	test.RegisterResourceUnauthorized(rest.T(), service.Context, service, controller, payload)

	_, created := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	test.ShowResourceUnauthorized(rest.T(), service.Context, service, controller, *created.ResourceID)
}

/*
 * This test will attempt to register a resource with an invalid parent resource
 */
func (rest *TestResourceREST) TestFailRegisterResourceInvalidParentResource() {
	resourceID := ""
	parentResourceID := uuid.NewV4().String()

	payload := &app.RegisterResourcePayload{
		ParentResourceID: &parentResourceID,
		ResourceID:       &resourceID,
		Type:             "openshift.io/resource/area",
	}

	test.RegisterResourceBadRequest(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)
}

func (rest *TestResourceREST) TestRegisterResourceCreated() {
	resourceID := ""

	payload := &app.RegisterResourcePayload{
		ParentResourceID: nil,
		ResourceID:       &resourceID,
		Type:             "openshift.io/resource/area",
	}

	_, created := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), created)
	require.NotNil(rest.T(), created.ResourceID)
}

func (rest *TestResourceREST) registerResourceCreatedWithAdmin(resourceType string, scopeToBeValidated string) {
	resourceID := uuid.NewV4().String()

	adminIdentity := rest.Graph.CreateUser().Identity()
	adminIdentityID := adminIdentity.ID.String()
	payload := &app.RegisterResourcePayload{
		ParentResourceID: nil,
		ResourceID:       &resourceID,
		Type:             resourceType,
		IdentityID:       &adminIdentityID,
	}

	_, created := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), created)
	require.NotNil(rest.T(), created.ResourceID)

	addedScopes, err := rest.Application.IdentityRoleRepository().FindScopesByIdentityAndResource(rest.Ctx, adminIdentity.ID, resourceID)
	require.Nil(rest.T(), err)
	require.Contains(rest.T(), addedScopes, scopeToBeValidated)
}

func (rest *TestResourceREST) TestRegisterSpaceResourceCreatedWithAdmin() {
	rest.registerResourceCreatedWithAdmin(authorization.ResourceTypeSpace, authorization.ManageSpaceScope)
}

func (rest *TestResourceREST) registerSystemResourceCreatedWithUserAdmin() {
	rest.registerResourceCreatedWithAdmin(authorization.ResourceTypeSystem, authorization.ManageUserSystemScope)
}

func (rest *TestResourceREST) TestRegisterSystemResourceCreatedWithUserAdmin() {
	rest.registerResourceCreatedWithAdmin(authorization.IdentityResourceTypeOrganization, authorization.ManageOrganizationMembersScope)
}

func (rest *TestResourceREST) TestRegisterOrgResourceCreatedWithInvalidIdentity() {
	resourceID := uuid.NewV4().String()

	adminIdentityID := "xyz"
	payload := &app.RegisterResourcePayload{
		ParentResourceID: nil,
		ResourceID:       &resourceID,
		Type:             "identity/organization",
		IdentityID:       &adminIdentityID,
	}

	test.RegisterResourceBadRequest(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)
}

func (rest *TestResourceREST) TestRegisterOrgResourceCreatedWithUserAdmin() {
	resourceID := uuid.NewV4().String()

	adminIdentity := rest.Graph.CreateUser().Identity()
	adminIdentityID := adminIdentity.ID.String()
	payload := &app.RegisterResourcePayload{
		ParentResourceID: nil,
		ResourceID:       &resourceID,
		Type:             "identity/organization",
		IdentityID:       &adminIdentityID,
	}

	_, created := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), created)
	require.NotNil(rest.T(), created.ResourceID)

	addedScopes, err := rest.Application.IdentityRoleRepository().FindScopesByIdentityAndResource(rest.Ctx, adminIdentity.ID, resourceID)
	require.NoError(rest.T(), err)
	require.Contains(rest.T(), addedScopes, authorization.ManageOrganizationMembersScope)
}

func (rest *TestResourceREST) TestRegisterResourceWithResourceIDSetCreated() {
	resourceID := uuid.NewV4().String()

	payload := &app.RegisterResourcePayload{
		ParentResourceID: nil,
		ResourceID:       &resourceID,
		Type:             "openshift.io/resource/area",
	}

	_, created := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), created)
	require.NotNil(rest.T(), created.ResourceID)
	require.EqualValues(rest.T(), *created.ResourceID, resourceID)

	_, readResource := test.ShowResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ResourceID)

	require.NotNil(rest.T(), readResource)
	require.NotNil(rest.T(), readResource.ResourceID)
	require.NotNil(rest.T(), readResource.Type)
	assert.EqualValues(rest.T(), resourceID, *readResource.ResourceID)
	assert.EqualValues(rest.T(), payload.Type, *readResource.Type)
}

func (rest *TestResourceREST) TestRegisterResourceWithInvalidResourceType() {
	resourceID := uuid.NewV4().String()

	payload := &app.RegisterResourcePayload{
		ParentResourceID: nil,
		ResourceID:       &resourceID,
		Type:             "invalid_type",
	}

	test.RegisterResourceBadRequest(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)
}

func (rest *TestResourceREST) TestRegisterResourceWithParentResourceSetCreated() {
	resourceID := ""

	// First we will create the parent resource
	payload := &app.RegisterResourcePayload{
		ParentResourceID: nil,
		ResourceID:       &resourceID,
		Type:             "openshift.io/resource/area",
	}

	_, parentCreated := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), parentCreated)
	require.NotNil(rest.T(), parentCreated.ResourceID)

	// Now we create the child resource
	payload = &app.RegisterResourcePayload{
		ParentResourceID: parentCreated.ResourceID,
		ResourceID:       &resourceID,
		Type:             "openshift.io/resource/area",
	}

	_, childCreated := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), childCreated)
	require.NotNil(rest.T(), childCreated.ResourceID)

	_, readResource := test.ShowResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *childCreated.ResourceID)

	require.EqualValues(rest.T(), payload.Type, "openshift.io/resource/area")
	require.EqualValues(rest.T(), payload.ParentResourceID, readResource.ParentResourceID)
}

func (rest *TestResourceREST) TestDeleteResource() {

	// Create the resource first
	payload := &app.RegisterResourcePayload{
		Type: "openshift.io/resource/area",
	}

	_, created := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), created)
	require.NotNil(rest.T(), created.ResourceID)

	_, readResource := test.ShowResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ResourceID)

	require.EqualValues(rest.T(), created.ResourceID, readResource.ResourceID)

	test.DeleteResourceNoContent(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ResourceID)

	test.ShowResourceNotFound(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ResourceID)
}

func (rest *TestResourceREST) TestScopesOK() {
	// Create a new resource type, with scope "foo"
	rt := rest.Graph.CreateResourceType()
	rt.AddScope("foo")
	rt.AddScope("bar")

	// Create a resource with the resource type
	res := rest.Graph.CreateResource(rt)

	// Create a role for the resource type with scope "foo"
	role := rest.Graph.CreateRole(rt)
	role.AddScope("foo")

	role2 := rest.Graph.CreateRole(rt)
	role2.AddScope("bar")

	// Create a user
	user := rest.Graph.CreateUser()

	// Assign the roles to the user
	rest.Graph.CreateIdentityRole(user, role, res)
	rest.Graph.CreateIdentityRole(user, role2, res)

	svc := testsupport.ServiceAsUser("Resource-Service", *user.Identity())
	ctrl := NewResourceController(svc, rest.Application)

	// Invoke the endpoint
	_, scopes := test.ScopesResourceOK(rest.T(), svc.Context, svc, ctrl, res.ResourceID())
	require.Len(rest.T(), scopes.Data, 2)
	fooFound := false
	barFound := false
	for _, scope := range scopes.Data {
		require.Equal(rest.T(), "user_resource_scope", scope.Type)
		if scope.ID == "foo" {
			fooFound = true
		} else if scope.ID == "bar" {
			barFound = true
		}
	}
	require.True(rest.T(), fooFound)
	require.True(rest.T(), barFound)

	// Create another user
	user2 := rest.Graph.CreateUser()

	svc = testsupport.ServiceAsUser("Resource-Service", *user2.Identity())
	ctrl = NewResourceController(svc, rest.Application)

	// There should be no scopes assigned for user2
	_, scopes = test.ScopesResourceOK(rest.T(), svc.Context, svc, ctrl, res.ResourceID())
	require.Len(rest.T(), scopes.Data, 0)
}

func (rest *TestResourceREST) TestScopesInvalidResourceIDNotFound() {
	user := rest.Graph.CreateUser()
	svc := testsupport.ServiceAsUser("Resource-Service", *user.Identity())
	ctrl := NewResourceController(svc, rest.Application)

	// An invalid resource ID should return a not found response
	test.ScopesResourceNotFound(rest.T(), svc.Context, svc, ctrl, uuid.NewV4().String())
}

func (rest *TestResourceREST) TestScopesUnauthorized() {
	svc := testsupport.UnsecuredService("Resource-Service")
	ctrl := NewResourceController(svc, rest.Application)

	res := rest.Graph.CreateResource()

	// The service is only available to authenticated users
	test.ScopesResourceUnauthorized(rest.T(), svc.Context, svc, ctrl, res.ResourceID())
}
