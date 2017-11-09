package controller_test

import (
	"fmt"
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/configuration"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	"github.com/goadesign/goa"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

var spaceConfiguration *configuration.ConfigurationData

func init() {
	var err error
	spaceConfiguration, err = configuration.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}
}

type TestSpaceREST struct {
	gormtestsupport.DBTestSuite
	db           *gormapplication.GormDB
	resourceID   string
	permissionID string
	policyID     string
}

func TestRunSpaceREST(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &TestSpaceREST{DBTestSuite: gormtestsupport.NewDBTestSuite("../config.yaml")})
}

func (rest *TestSpaceREST) SetupTest() {
	rest.DBTestSuite.SetupTest()
	rest.db = gormapplication.NewGormDB(rest.DB)
	rest.resourceID = uuid.NewV4().String()
	rest.permissionID = uuid.NewV4().String()
	rest.policyID = uuid.NewV4().String()
}

func (rest *TestSpaceREST) SecuredController(identity account.Identity) (*goa.Service, *SpaceController) {
	svc := testsupport.ServiceAsUser("Space-Service", identity)
	return svc, NewSpaceController(svc, rest.db, spaceConfiguration, &DummyResourceManager{
		ResourceID:   &rest.resourceID,
		PermissionID: &rest.permissionID,
		PolicyID:     &rest.policyID,
	})
}

func (rest *TestSpaceREST) UnSecuredController() (*goa.Service, *SpaceController) {
	svc := goa.New("Space-Service")
	return svc, NewSpaceController(svc, rest.db, spaceConfiguration, &DummyResourceManager{
		ResourceID:   &rest.resourceID,
		PermissionID: &rest.permissionID,
		PolicyID:     &rest.policyID,
	})
}

func (rest *TestSpaceREST) TestFailCreateSpaceUnauthorized() {
	// given
	svc, ctrl := rest.UnSecuredController()
	// when/then
	test.CreateSpaceUnauthorized(rest.T(), svc.Context, svc, ctrl, uuid.NewV4())
}

func (rest *TestSpaceREST) TestCreateSpaceOK() {
	// given
	svc, ctrl := rest.SecuredController(testsupport.TestIdentity)
	// when
	_, created := test.CreateSpaceOK(rest.T(), svc.Context, svc, ctrl, uuid.NewV4())
	// then
	require.NotNil(rest.T(), created.Data)
	assert.Equal(rest.T(), rest.resourceID, created.Data.ResourceID)
	assert.Equal(rest.T(), rest.permissionID, created.Data.PermissionID)
	assert.Equal(rest.T(), rest.policyID, created.Data.PolicyID)
}

func (rest *TestSpaceREST) TestFailDeleteSpaceUnauthorized() {
	// given
	svc, ctrl := rest.UnSecuredController()
	// when/then
	test.DeleteSpaceUnauthorized(rest.T(), svc.Context, svc, ctrl, uuid.NewV4())
}

func (rest *TestSpaceREST) TestDeleteSpaceOK() {
	// given
	svc, ctrl := rest.SecuredController(testsupport.TestIdentity)
	id := uuid.NewV4()
	// when
	test.CreateSpaceOK(rest.T(), svc.Context, svc, ctrl, id)
	// then
	test.DeleteSpaceOK(rest.T(), svc.Context, svc, ctrl, id)
}

func (rest *TestSpaceREST) TestDeleteSpaceIfUserIsNotSpaceOwnerForbidden() {
	// given
	svcOwner, ctrlOwner := rest.SecuredController(testsupport.TestIdentity)
	svcNotOwner, ctrlNotOwner := rest.SecuredController(testsupport.TestIdentity2)
	id := uuid.NewV4()
	// when
	test.CreateSpaceOK(rest.T(), svcOwner.Context, svcOwner, ctrlOwner, id)
	// then
	test.DeleteSpaceForbidden(rest.T(), svcNotOwner.Context, svcNotOwner, ctrlNotOwner, id)
}
