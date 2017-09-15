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
	authtoken "github.com/fabric8-services/fabric8-auth/token"
	"github.com/goadesign/goa"
	//"github.com/stretchr/testify/assert"
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
	suite.Run(t, &TestResourceREST{DBTestSuite: gormtestsupport.NewDBTestSuite("../config.yaml")})
}

func (rest *TestResourceREST) SetupTest() {
	rest.db = gormapplication.NewGormDB(rest.DB)
	rest.clean = cleaner.DeleteCreatedEntities(rest.DB)
}

func (rest *TestResourceREST) TearDownTest() {
	rest.clean()
}

func (rest *TestResourceREST) SecuredController(identity account.Identity) (*goa.Service, *ResourceController) {
	priv, _ := authtoken.ParsePrivateKey([]byte(authtoken.RSAPrivateKey))

	svc := testsupport.ServiceAsUser("Resource-Service", authtoken.NewManagerWithPrivateKey(priv), identity)
	return svc, NewResourceController(svc, rest.db)
}

func (rest *TestResourceREST) UnSecuredController() (*goa.Service, *ResourceController) {
	svc := goa.New("Resource-Service")
	return svc, NewResourceController(svc, rest.db)
}

/*
 * This test will attempt to register a resource with an invalid PAT
 */
func (rest *TestResourceREST) TestFailRegisterResourceBadRequest() {

	svc, ctrl := rest.UnSecuredController()

	resourceDescription := "Resource description"
	resourceID := ""
	resourceScopes := []string{}

	// Assign an invalid owner ID
	resourceOwnerID := "xxx1234"

	payload := &app.RegisterResourcePayload{
		Description:      &resourceDescription,
		Name:             "My new resource",
		ParentResourceID: nil,
		ResourceScopes:   resourceScopes,
		ResourceID:       &resourceID,
		ResourceOwnerID:  resourceOwnerID,
		Type:             "Area",
	}

	test.RegisterResourceBadRequest(rest.T(), svc.Context, svc, ctrl, payload)
}

func (rest *TestResourceREST) TestRegisterResourceCreated() {

	testIdentity, err := testsupport.CreateTestIdentity(rest.DB, "TestRegisterResourceCreated-"+uuid.NewV4().String(), "TestRegisterResourceCreated")
	require.Nil(rest.T(), err)
	svc, ctrl := rest.SecuredController(testIdentity)

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

	fmt.Println("Creating...")
	_, created := test.RegisterResourceCreated(rest.T(), svc.Context, svc, ctrl, payload)
	// then
	fmt.Println("...Created")
	require.NotNil(rest.T(), created)
	require.NotNil(rest.T(), created.ID)
}

func (rest *TestResourceREST) TestRegisterResourceNotFound() {

	svc, ctrl := rest.SecuredController(testsupport.TestIdentity)

	resourceDescription := "Resource description"
	resourceID := ""
	resourceScopes := []string{}
	resourceOwnerID := uuid.NewV4() // unknown identity

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
	test.RegisterResourceNotFound(rest.T(), svc.Context, svc, ctrl, payload)
}
