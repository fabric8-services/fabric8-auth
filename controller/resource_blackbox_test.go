package controller_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"

	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/goadesign/goa"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestResourceREST struct {
	gormtestsupport.DBTestSuite
	testIdentity      account.Identity
	service           *goa.Service
	securedController *ResourceController
}

func (s *TestResourceREST) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	var err error
	s.testIdentity, err = testsupport.CreateTestIdentity(s.DB,
		"TestRegisterResourceCreated-"+uuid.NewV4().String(),
		"TestRegisterResourceCreated")
	require.Nil(s.T(), err)

	sa := account.Identity{
		Username: "fabric8-wit",
	}
	s.service = testsupport.ServiceAsServiceAccountUser("Resource-Service", sa)
	s.securedController = NewResourceController(s.service, s.Application)
}

func TestRunResourceREST(t *testing.T) {
	suite.Run(t, &TestResourceREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestResourceREST) SecuredController(identity account.Identity) (*goa.Service, *ResourceController) {
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
	resourceScopes := []string{}

	resourceOwnerID := rest.testIdentity.ID

	payload := &app.RegisterResourcePayload{
		Name:             "My new resource",
		ParentResourceID: nil,
		ResourceScopes:   resourceScopes,
		ResourceID:       &resourceID,
		ResourceOwnerID:  resourceOwnerID.String(),
		Type:             "openshift.io/resource/area",
	}

	test.RegisterResourceUnauthorized(rest.T(), service.Context, service, controller, payload)

	_, created := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	test.ReadResourceUnauthorized(rest.T(), service.Context, service, controller, *created.ID)
}

/*
 * This test will attempt to register a resource with an invalid parent resource
 */
func (rest *TestResourceREST) TestFailRegisterResourceInvalidParentResource() {
	resourceID := ""
	resourceScopes := []string{}

	resourceOwnerID := rest.testIdentity.ID
	parentResourceID := uuid.NewV4().String()

	payload := &app.RegisterResourcePayload{
		Name:             "My new resource",
		ParentResourceID: &parentResourceID,
		ResourceScopes:   resourceScopes,
		ResourceID:       &resourceID,
		ResourceOwnerID:  resourceOwnerID.String(),
		Type:             "openshift.io/resource/area",
	}

	test.RegisterResourceBadRequest(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)
}

func (rest *TestResourceREST) TestRegisterResourceCreated() {
	resourceID := ""
	resourceScopes := []string{}
	resourceOwnerID := rest.testIdentity.ID

	payload := &app.RegisterResourcePayload{
		Name:             "My new resource",
		ParentResourceID: nil,
		ResourceScopes:   resourceScopes,
		ResourceID:       &resourceID,
		ResourceOwnerID:  resourceOwnerID.String(),
		Type:             "openshift.io/resource/area",
	}

	_, created := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), created)
	require.NotNil(rest.T(), created.ID)
}

func (rest *TestResourceREST) TestRegisterResourceWithResourceIDSetCreated() {
	resourceID := uuid.NewV4().String()
	resourceScopes := []string{}
	resourceOwnerID := rest.testIdentity.ID

	payload := &app.RegisterResourcePayload{
		Name:             "My new resource",
		ParentResourceID: nil,
		ResourceScopes:   resourceScopes,
		ResourceID:       &resourceID,
		ResourceOwnerID:  resourceOwnerID.String(),
		Type:             "openshift.io/resource/area",
	}

	_, created := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), created)
	require.NotNil(rest.T(), created.ID)
	require.EqualValues(rest.T(), *created.ID, resourceID)

	_, readResource := test.ReadResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ID)

	require.EqualValues(rest.T(), payload.Name, readResource.Name)
}

func (rest *TestResourceREST) TestRegisterResourceWithInvalidResourceType() {
	resourceID := uuid.NewV4().String()
	resourceScopes := []string{}
	resourceOwnerID := rest.testIdentity.ID

	payload := &app.RegisterResourcePayload{
		Name:             "My invalid resource",
		ParentResourceID: nil,
		ResourceScopes:   resourceScopes,
		ResourceID:       &resourceID,
		ResourceOwnerID:  resourceOwnerID.String(),
		Type:             "invalid_type",
	}

	_, _ = test.RegisterResourceBadRequest(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)
}

func (rest *TestResourceREST) TestRegisterResourceWithParentResourceSetCreated() {
	resourceID := ""
	resourceScopes := []string{}
	resourceOwnerID := rest.testIdentity.ID

	// First we will create the parent resource
	payload := &app.RegisterResourcePayload{
		Name:             "My new parent resource",
		ParentResourceID: nil,
		ResourceScopes:   resourceScopes,
		ResourceID:       &resourceID,
		ResourceOwnerID:  resourceOwnerID.String(),
		Type:             "openshift.io/resource/area",
	}

	_, parentCreated := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), parentCreated)
	require.NotNil(rest.T(), parentCreated.ID)

	// Now we create the child resource
	payload = &app.RegisterResourcePayload{
		Name:             "My new child resource",
		ParentResourceID: parentCreated.ID,
		ResourceScopes:   resourceScopes,
		ResourceID:       &resourceID,
		ResourceOwnerID:  resourceOwnerID.String(),
		Type:             "openshift.io/resource/area",
	}

	_, childCreated := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), childCreated)
	require.NotNil(rest.T(), childCreated.ID)

	_, readResource := test.ReadResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *childCreated.ID)

	require.EqualValues(rest.T(), payload.Name, readResource.Name)
	require.EqualValues(rest.T(), payload.Type, "openshift.io/resource/area")
	require.EqualValues(rest.T(), payload.ParentResourceID, parentCreated.ID)
	require.EqualValues(rest.T(), payload.ResourceOwnerID, resourceOwnerID.String())
}

func (rest *TestResourceREST) TestFailRegisterResourceUnknownOwner() {
	resourceID := ""
	resourceScopes := []string{}

	// Attempt to register the resource with an unknown owner
	resourceOwnerID := uuid.NewV4()

	payload := &app.RegisterResourcePayload{
		Name:             "My new resource",
		ParentResourceID: nil,
		ResourceScopes:   resourceScopes,
		ResourceID:       &resourceID,
		ResourceOwnerID:  resourceOwnerID.String(),
		Type:             "openshift.io/resource/area",
	}

	test.RegisterResourceNotFound(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)
}

func (rest *TestResourceREST) TestUpdateResource() {
	// Create the resource first
	payload := &app.RegisterResourcePayload{
		Name:             "Resource_Alpha",
		ParentResourceID: nil,
		ResourceScopes:   []string{},
		ResourceOwnerID:  rest.testIdentity.ID.String(),
		Type:             "openshift.io/resource/area",
	}

	_, created := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), created)
	require.NotNil(rest.T(), created.ID)

	_, readResource := test.ReadResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ID)

	require.EqualValues(rest.T(), created.ID, readResource.ResourceID)
	require.EqualValues(rest.T(), payload.Name, readResource.Name)

	var updatedName = "Resource_Bravo"
	updatePayload := &app.UpdateResourcePayload{
		Name: &updatedName,
	}

	_, updated := test.UpdateResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ID, updatePayload)

	// First confirm we get the correct resource ID back in the response
	require.EqualValues(rest.T(), created.ID, updated.ID)

	// Read the resource again, and check the name has been updated
	_, readResource = test.ReadResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ID)
	require.EqualValues(rest.T(), updatedName, readResource.Name)

	// Also confirm that no other fields have been updated
	require.EqualValues(rest.T(), "openshift.io/resource/area", readResource.Type)

	// Set the type to an invalid type and try to update it
	invalidType := "invalid-type"
	updatePayload = &app.UpdateResourcePayload{
		Type: &invalidType,
	}
	test.UpdateResourceBadRequest(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ID, updatePayload)

	// Create another resource - we will use this as the parent
	parentPayload := &app.RegisterResourcePayload{
		Name:             "Resource_Parent",
		ParentResourceID: nil,
		ResourceScopes:   []string{},
		ResourceOwnerID:  rest.testIdentity.ID.String(),
		Type:             "openshift.io/resource/area",
	}

	// Create the parent resource
	_, parentCreated := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, parentPayload)

	// Confirm it was created successfully
	require.NotNil(rest.T(), parentCreated)
	require.NotNil(rest.T(), parentCreated.ID)

	// Now test setting the original resource's parent to the newly created resource
	updatePayload = &app.UpdateResourcePayload{
		ParentResourceID: parentCreated.ID,
	}

	// Update the original resource
	_, updated = test.UpdateResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ID, updatePayload)

	// Read the resource again, and check the parent resource has been updated
	_, readResource = test.ReadResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ID)

	require.EqualValues(rest.T(), *parentCreated.ID, *readResource.ParentResourceID)
}

func (rest *TestResourceREST) TestDeleteResource() {

	// Create the resource first
	payload := &app.RegisterResourcePayload{
		Name:            "My new resource",
		ResourceScopes:  []string{},
		ResourceOwnerID: rest.testIdentity.ID.String(),
		Type:            "openshift.io/resource/area",
	}

	_, created := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), created)
	require.NotNil(rest.T(), created.ID)

	_, readResource := test.ReadResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ID)

	require.EqualValues(rest.T(), created.ID, readResource.ResourceID)

	test.DeleteResourceNoContent(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ID)

	test.ReadResourceNotFound(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ID)

}
