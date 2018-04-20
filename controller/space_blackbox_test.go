package controller_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestSpaceREST struct {
	gormtestsupport.DBTestSuite
	resourceID   string
	permissionID string
	policyID     string
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
}

func (rest *TestSpaceREST) SecuredController() (*goa.Service, *SpaceController) {
	identity, err := testsupport.CreateTestIdentityAndUser(rest.DB, uuid.NewV4().String(), "KC")
	require.NoError(rest.T(), err)

	svc := testsupport.ServiceAsUser("Space-Service", identity)
	return svc, NewSpaceController(svc, rest.Application, rest.Configuration, &DummyResourceManager{
		ResourceID:   &rest.resourceID,
		PermissionID: &rest.permissionID,
		PolicyID:     &rest.policyID,
	})
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
	test.CreateSpaceUnauthorized(rest.T(), svc.Context, svc, ctrl, uuid.NewV4())
}

func (rest *TestSpaceREST) TestCreateSpaceUnauthorizedDeprovisionedUser() {
	// given
	svc, ctrl := rest.UnSecuredControllerWithDeprovisionedIdentity()
	// when/then
	test.CreateSpaceUnauthorized(rest.T(), svc.Context, svc, ctrl, uuid.NewV4())
}

func (rest *TestSpaceREST) TestCreateSpaceOK() {
	// given
	svc, ctrl := rest.SecuredController()
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

func (rest *TestSpaceREST) TestDeleteSpaceUnauthorizedDeprovisionedUser() {
	// given
	svc, ctrl := rest.UnSecuredControllerWithDeprovisionedIdentity()
	// when/then
	test.DeleteSpaceUnauthorized(rest.T(), svc.Context, svc, ctrl, uuid.NewV4())
}

func (rest *TestSpaceREST) TestDeleteSpaceOK() {
	// given
	svc, ctrl := rest.SecuredController()
	id := uuid.NewV4()
	// when
	test.CreateSpaceOK(rest.T(), svc.Context, svc, ctrl, id)
	// then
	test.DeleteSpaceOK(rest.T(), svc.Context, svc, ctrl, id)
}

func (rest *TestSpaceREST) TestDeleteSpaceIfUserIsNotSpaceOwnerForbidden() {
	// given
	svcOwner, ctrlOwner := rest.SecuredController()
	svcNotOwner, ctrlNotOwner := rest.SecuredController()
	id := uuid.NewV4()
	// when
	test.CreateSpaceOK(rest.T(), svcOwner.Context, svcOwner, ctrlOwner, id)
	// then
	test.DeleteSpaceForbidden(rest.T(), svcNotOwner.Context, svcNotOwner, ctrlNotOwner, id)
}
