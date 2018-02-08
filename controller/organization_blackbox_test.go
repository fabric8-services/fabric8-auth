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

type TestOrganizationREST struct {
	gormtestsupport.DBTestSuite
	testIdentity      account.Identity
	service           *goa.Service
	securedController *OrganizationController
}

func (s *TestOrganizationREST) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	var err error
	s.testIdentity, err = testsupport.CreateTestIdentity(s.DB,
		"TestOrganizationCreated-"+uuid.NewV4().String(),
		"TestOrganization")
	require.Nil(s.T(), err)

	sa := account.Identity{
		Username: "fabric8-wit",
	}
	s.service = testsupport.ServiceAsServiceAccountUser("Organization-Service", sa)
	s.securedController = NewOrganizationController(s.service, s.Application)
}

func TestRunOrganizationREST(t *testing.T) {
	suite.Run(t, &TestOrganizationREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestOrganizationREST) SecuredController(identity account.Identity) (*goa.Service, *OrganizationController) {
	svc := testsupport.ServiceAsUser("Organization-Service", identity)
	return svc, NewOrganizationController(svc, rest.Application)
}

/*
* This test will attempt to create a new organization
 */
func (rest *TestOrganizationREST) TestCreateOrganizationSuccess() {

	service, controller := rest.SecuredController(rest.testIdentity)

	orgName := "Acme Corporation"

	payload := &app.CreateOrganizationPayload{
		Name: &orgName,
	}

	_, created := test.CreateOrganizationCreated(rest.T(), service.Context, service, controller, payload)

	require.NotEmpty(rest.T(), created.OrganizationID)
}

/*
* This test will attempt to create a new organization
 */
func (rest *TestOrganizationREST) TestCreateOrganizationEmptyNameFail() {

	service, controller := rest.SecuredController(rest.testIdentity)

	orgName := ""

	payload := &app.CreateOrganizationPayload{
		Name: &orgName,
	}

	_, err := test.CreateOrganizationBadRequest(rest.T(), service.Context, service, controller, payload)

	require.NotNil(rest.T(), err)
}

/*
* This test will attempt to create a new organization
 */
func (rest *TestOrganizationREST) TestCreateOrganizationUnauthorizedFail() {
	/*sa := account.Identity{
		Username: "unknown-account",
	}
	service, controller := rest.SecuredController(sa)

	orgName := "Acme Corporation"

	payload := &app.CreateOrganizationPayload{
		Name: &orgName,
	}

	_, err := test.CreateOrganizationUnauthorized(rest.T(), service.Context, service, controller, payload)

	require.NotNil(rest.T(), err)*/
}
