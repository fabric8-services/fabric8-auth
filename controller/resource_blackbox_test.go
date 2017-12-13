package controller_test

import (
	"fmt"
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

func init() {
	var err error
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}
}

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

	resourceDescription := "Resource description"
	resourceID := ""
	resourceScopes := []string{}

	resourceOwnerID := rest.testIdentity.ID

	payload := &app.RegisterResourcePayload{
		Description:      &resourceDescription,
		Name:             "My new resource",
		ParentResourceID: nil,
		ResourceScopes:   resourceScopes,
		ResourceID:       &resourceID,
		ResourceOwnerID:  resourceOwnerID.String(),
		Type:             "Area",
	}

	test.RegisterResourceUnauthorized(rest.T(), service.Context, service, controller, payload)
}

/*
 * This test will attempt to register a resource with an invalid parent resource
 */
func (rest *TestResourceREST) TestFailRegisterResourceInvalidParentResource() {
	resourceDescription := "Resource description"
	resourceID := ""
	resourceScopes := []string{}

	resourceOwnerID := rest.testIdentity.ID
	parentResourceID := uuid.NewV4().String()

	payload := &app.RegisterResourcePayload{
		Description:      &resourceDescription,
		Name:             "My new resource",
		ParentResourceID: &parentResourceID,
		ResourceScopes:   resourceScopes,
		ResourceID:       &resourceID,
		ResourceOwnerID:  resourceOwnerID.String(),
		Type:             "Area",
	}

	test.RegisterResourceBadRequest(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)
}

func (rest *TestResourceREST) TestRegisterResourceCreated() {
	resourceDescription := "Resource description"
	resourceID := ""
	resourceScopes := []string{}
	resourceOwnerID := rest.testIdentity.ID

	payload := &app.RegisterResourcePayload{
		Description:      &resourceDescription,
		Name:             "My new resource",
		ParentResourceID: nil,
		ResourceScopes:   resourceScopes,
		ResourceID:       &resourceID,
		ResourceOwnerID:  resourceOwnerID.String(),
		Type:             "Area",
	}

	_, created := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), created)
	require.NotNil(rest.T(), created.ID)
}

func (rest *TestResourceREST) TestRegisterResourceWithResourceIDSetCreated() {
	resourceDescription := "Resource description"
	resourceID := uuid.NewV4().String()
	resourceScopes := []string{}
	resourceOwnerID := rest.testIdentity.ID

	payload := &app.RegisterResourcePayload{
		Description:      &resourceDescription,
		Name:             "My new resource",
		ParentResourceID: nil,
		ResourceScopes:   resourceScopes,
		ResourceID:       &resourceID,
		ResourceOwnerID:  resourceOwnerID.String(),
		Type:             "Area",
	}

	_, created := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), created)
	require.NotNil(rest.T(), created.ID)
	require.EqualValues(rest.T(), *created.ID, resourceID)
}

func (rest *TestResourceREST) TestRegisterResourceWithParentResourceSetCreated() {
	resourceDescription := "Parent Resource Description"
	resourceID := ""
	resourceScopes := []string{}
	resourceOwnerID := rest.testIdentity.ID

	// First we will create the parent resource
	payload := &app.RegisterResourcePayload{
		Description:      &resourceDescription,
		Name:             "My new parent resource",
		ParentResourceID: nil,
		ResourceScopes:   resourceScopes,
		ResourceID:       &resourceID,
		ResourceOwnerID:  resourceOwnerID.String(),
		Type:             "Area",
	}

	_, parentCreated := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), parentCreated)
	require.NotNil(rest.T(), parentCreated.ID)

	// Now we create the child resource
	resourceDescription = "Child Resource Description"

	payload = &app.RegisterResourcePayload{
		Description:      &resourceDescription,
		Name:             "My new child resource",
		ParentResourceID: parentCreated.ID,
		ResourceScopes:   resourceScopes,
		ResourceID:       &resourceID,
		ResourceOwnerID:  resourceOwnerID.String(),
		Type:             "Area",
	}

	_, childCreated := test.RegisterResourceCreated(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)

	require.NotNil(rest.T(), childCreated)
	require.NotNil(rest.T(), childCreated.ID)
}

func (rest *TestResourceREST) TestFailRegisterResourceUnknownOwner() {
	resourceDescription := "Resource description"
	resourceID := ""
	resourceScopes := []string{}

	// Attempt to register the resource with an unknown owner
	resourceOwnerID := uuid.NewV4()

	payload := &app.RegisterResourcePayload{
		Description:      &resourceDescription,
		Name:             "My new resource",
		ParentResourceID: nil,
		ResourceScopes:   resourceScopes,
		ResourceID:       &resourceID,
		ResourceOwnerID:  resourceOwnerID.String(),
		Type:             "Area",
	}

	test.RegisterResourceNotFound(rest.T(), rest.service.Context, rest.service, rest.securedController, payload)
}
