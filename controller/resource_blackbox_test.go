package controller_test

import (
	"fmt"
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/configuration"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormsupport/cleaner"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"

	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/goadesign/goa"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

var resourceConfiguration *configuration.ConfigurationData

func init() {
	var err error
	resourceConfiguration, err = configuration.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}
}

type TestResourceREST struct {
	gormtestsupport.DBTestSuite
	db    *gormapplication.GormDB
	clean func()
}

func TestRunResourceREST(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &TestResourceREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestResourceREST) SetupTest() {
	rest.db = gormapplication.NewGormDB(rest.DB)
	rest.clean = cleaner.DeleteCreatedEntities(rest.DB)
}

func (rest *TestResourceREST) TearDownTest() {
	rest.clean()
}

func (rest *TestResourceREST) SecuredController(identity account.Identity) (*goa.Service, *ResourceController) {
	svc := testsupport.ServiceAsUser("Resource-Service", identity)
	return svc, NewResourceController(svc, rest.db)
}

func (rest *TestResourceREST) SecuredControllerWithServiceAccount(serviceAccount account.Identity) (*goa.Service, *ResourceController) {
	svc := testsupport.ServiceAsServiceAccountUser("Resource-Service", serviceAccount)
	return svc, NewResourceController(svc, rest.Application)
}

func (rest *TestResourceREST) UnSecuredController() (*goa.Service, *ResourceController) {
	svc := goa.New("Resource-Service")
	return svc, NewResourceController(svc, rest.db)
}

/*
 * This test will attempt to register a resource with an invalid account
 */
func (rest *TestResourceREST) TestFailRegisterResourceNonServiceAccount() {
	testIdentity, err := testsupport.CreateTestIdentity(rest.DB, "TestRegisterResourceCreated-"+uuid.NewV4().String(), "TestRegisterResourceCreated")
	require.Nil(rest.T(), err)

	sa := account.Identity{
		Username: "unknown-sa",
	}
	service, controller := rest.SecuredController(sa)

	resourceDescription := "Resource description"
	resourceID := ""
	resourceScopes := []string{}

	resourceOwnerID := testIdentity.ID

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
	testIdentity, err := testsupport.CreateTestIdentity(rest.DB, "TestRegisterResourceCreated-"+uuid.NewV4().String(), "TestRegisterResourceCreated")
	require.Nil(rest.T(), err)

	sa := account.Identity{
		Username: "fabric8-wit",
	}
	service, controller := rest.SecuredControllerWithServiceAccount(sa)

	resourceDescription := "Resource description"
	resourceID := ""
	resourceScopes := []string{}

	resourceOwnerID := testIdentity.ID
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

	test.RegisterResourceBadRequest(rest.T(), service.Context, service, controller, payload)
}

func (rest *TestResourceREST) TestRegisterResourceCreated() {

	testIdentity, err := testsupport.CreateTestIdentity(rest.DB, "TestRegisterResourceCreated-"+uuid.NewV4().String(), "TestRegisterResourceCreated")
	require.Nil(rest.T(), err)

	sa := account.Identity{
		Username: "fabric8-wit",
	}
	service, controller := rest.SecuredControllerWithServiceAccount(sa)

	resourceDescription := "Resource description"
	resourceID := ""
	resourceScopes := []string{}
	resourceOwnerID := testIdentity.ID

	fmt.Printf("!!!!!! ID: %v\n", resourceOwnerID)

	payload := &app.RegisterResourcePayload{
		Description:      &resourceDescription,
		Name:             "My new resource",
		ParentResourceID: nil,
		ResourceScopes:   resourceScopes,
		ResourceID:       &resourceID,
		ResourceOwnerID:  resourceOwnerID.String(),
		Type:             "Area",
	}

	fmt.Println("Creating...")
	_, created := test.RegisterResourceCreated(rest.T(), service.Context, service, controller, payload)
	// then
	fmt.Println("...Created")
	require.NotNil(rest.T(), created)
	require.NotNil(rest.T(), created.ID)
}

func (rest *TestResourceREST) TestRegisterResourceWithResourceIDSetCreated() {
	testIdentity, err := testsupport.CreateTestIdentity(rest.DB, "TestRegisterResourceCreated-"+uuid.NewV4().String(), "TestRegisterResourceCreated")
	require.Nil(rest.T(), err)

	sa := account.Identity{
		Username: "fabric8-wit",
	}
	service, controller := rest.SecuredControllerWithServiceAccount(sa)

	resourceDescription := "Resource description"
	resourceID := uuid.NewV4().String()
	resourceScopes := []string{}
	resourceOwnerID := testIdentity.ID

	fmt.Printf("!!!!!! ID: %v\n", resourceOwnerID)

	payload := &app.RegisterResourcePayload{
		Description:      &resourceDescription,
		Name:             "My new resource",
		ParentResourceID: nil,
		ResourceScopes:   resourceScopes,
		ResourceID:       &resourceID,
		ResourceOwnerID:  resourceOwnerID.String(),
		Type:             "Area",
	}

	fmt.Println("Creating...")
	_, created := test.RegisterResourceCreated(rest.T(), service.Context, service, controller, payload)
	// then
	fmt.Println("...Created")
	require.NotNil(rest.T(), created)
	require.NotNil(rest.T(), created.ID)
	require.EqualValues(rest.T(), *created.ID, resourceID)
}

func (rest *TestResourceREST) TestRegisterResourceWithParentResourceSetCreated() {
	testIdentity, err := testsupport.CreateTestIdentity(rest.DB, "TestRegisterResourceCreated-"+uuid.NewV4().String(), "TestRegisterResourceCreated")
	require.Nil(rest.T(), err)

	sa := account.Identity{
		Username: "fabric8-wit",
	}
	service, controller := rest.SecuredControllerWithServiceAccount(sa)

	resourceDescription := "Parent Resource Description"
	resourceID := ""
	resourceScopes := []string{}
	resourceOwnerID := testIdentity.ID

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

	_, parentCreated := test.RegisterResourceCreated(rest.T(), service.Context, service, controller, payload)

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

	_, childCreated := test.RegisterResourceCreated(rest.T(), service.Context, service, controller, payload)

	require.NotNil(rest.T(), childCreated)
	require.NotNil(rest.T(), childCreated.ID)
}

func (rest *TestResourceREST) TestFailRegisterResourceUnknownOwner() {

	sa := account.Identity{
		Username: "fabric8-wit",
	}
	service, controller := rest.SecuredControllerWithServiceAccount(sa)

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

	fmt.Println("Creating...")
	test.RegisterResourceNotFound(rest.T(), service.Context, service, controller, payload)
}
