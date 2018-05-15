package controller_test

import (
	"testing"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
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

	test.ReadResourceUnauthorized(rest.T(), service.Context, service, controller, *created.ResourceID)
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

	_, readResource := test.ReadResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ResourceID)

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

	_, readResource := test.ReadResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *childCreated.ResourceID)

	require.EqualValues(rest.T(), payload.Type, "openshift.io/resource/area")
	require.EqualValues(rest.T(), payload.ParentResourceID, readResource.ParentResourceID)
}

func (rest *TestResourceREST) TestUpdateResource() {
	// Create the resource first
	payload := &app.RegisterResourcePayload{
		ParentResourceID: nil,
		Type:             "openshift.io/resource/area",
	}

	_, created := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), created)
	require.NotNil(rest.T(), created.ResourceID)

	_, readCreatedResource := test.ReadResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ResourceID)

	require.EqualValues(rest.T(), created.ResourceID, readCreatedResource.ResourceID)

	// Create another resource - we will use this as the parent
	parentPayload := &app.RegisterResourcePayload{
		ParentResourceID: nil,
		Type:             "openshift.io/resource/area",
	}

	// Create the parent resource
	_, parentCreated := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, parentPayload)

	// Confirm it was created successfully
	require.NotNil(rest.T(), parentCreated)
	require.NotNil(rest.T(), parentCreated.ResourceID)

	// Now test setting the original resource's parent to the newly created resource
	updatePayload := &app.UpdateResourcePayload{
		ParentResourceID: *parentCreated.ResourceID,
	}

	// Update the original resource
	_, updated := test.UpdateResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ResourceID, updatePayload)
	require.EqualValues(rest.T(), created.ResourceID, updated.ResourceID)

	// Read the resource again, and check the parent resource has been updated
	_, readResource := test.ReadResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ResourceID)

	require.EqualValues(rest.T(), *parentCreated.ResourceID, *readResource.ParentResourceID)

	// Now test clearing the original resource's parent to nil
	updatePayload = &app.UpdateResourcePayload{
		ParentResourceID: "",
	}

	// Update the original resource
	_, updated = test.UpdateResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ResourceID, updatePayload)

	// Read the resource again, and check the parent resource has been cleared
	_, readResource = test.ReadResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ResourceID)

	require.Nil(rest.T(), readResource.ParentResourceID)
}

func (rest *TestResourceREST) TestDeleteResource() {

	// Create the resource first
	payload := &app.RegisterResourcePayload{
		Type: "openshift.io/resource/area",
	}

	_, created := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), created)
	require.NotNil(rest.T(), created.ResourceID)

	_, readResource := test.ReadResourceOK(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ResourceID)

	require.EqualValues(rest.T(), created.ResourceID, readResource.ResourceID)

	test.DeleteResourceNoContent(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ResourceID)

	test.ReadResourceNotFound(rest.T(), rest.service.Context, rest.service, rest.securedController, *created.ResourceID)

}
