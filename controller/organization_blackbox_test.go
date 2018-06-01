package controller_test

import (
	"testing"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestOrganizationREST struct {
	gormtestsupport.DBTestSuite
	testIdentity account.Identity
	service      *goa.Service
}

func (s *TestOrganizationREST) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	var err error
	s.testIdentity, err = testsupport.CreateTestIdentity(s.DB,
		"OrganizationCreatorUser-"+uuid.NewV4().String(),
		"TestOrganization")
	require.Nil(s.T(), err)
}

func TestRunOrganizationREST(t *testing.T) {
	suite.Run(t, &TestOrganizationREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestOrganizationREST) SecuredController(identity account.Identity) (*goa.Service, *OrganizationController) {
	svc := testsupport.ServiceAsUser("Organization-Service", identity)
	return svc, NewOrganizationController(svc, rest.Application)
}

func (rest *TestOrganizationREST) UnsecuredController() (*goa.Service, *OrganizationController) {
	svc := goa.New("Organization-Service")
	controller := NewOrganizationController(svc, rest.Application)
	return svc, controller
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

func (rest *TestOrganizationREST) TestCreateOrganizationUnauthorized() {
	service, controller := rest.UnsecuredController()

	orgName := "Unauthorized Organization Creation"
	payload := &app.CreateOrganizationPayload{
		Name: &orgName,
	}

	test.CreateOrganizationUnauthorized(rest.T(), service.Context, service, controller, payload)
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
func (rest *TestOrganizationREST) TestListOrganizationSuccess() {

	service, controller := rest.SecuredController(rest.testIdentity)

	orgName := "Acme Corporation"

	payload := &app.CreateOrganizationPayload{
		Name: &orgName,
	}

	_, created := test.CreateOrganizationCreated(rest.T(), service.Context, service, controller, payload)

	require.NotEmpty(rest.T(), created.OrganizationID)

	_, orgs := test.ListOrganizationOK(rest.T(), service.Context, service, controller)

	require.Equal(rest.T(), 1, len(orgs.Data))

	org := orgs.Data[0]

	require.Equal(rest.T(), *created.OrganizationID, org.ID)
	require.Equal(rest.T(), orgName, org.Name)
	require.Equal(rest.T(), 1, len(org.Roles))
	require.Equal(rest.T(), authorization.OrganizationAdminRole, org.Roles[0])
}

func (rest *TestOrganizationREST) TestListOrganizationUnauthorized() {
	service, controller := rest.UnsecuredController()
	test.ListOrganizationUnauthorized(rest.T(), service.Context, service, controller)
}
