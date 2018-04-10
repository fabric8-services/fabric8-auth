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

	invitationmodel "github.com/fabric8-services/fabric8-auth/authorization/invitation/model"
	invitationrepo "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	invitationservice "github.com/fabric8-services/fabric8-auth/authorization/invitation/service"
	permissionmodel "github.com/fabric8-services/fabric8-auth/authorization/permission/model"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestInvitationREST struct {
	gormtestsupport.DBTestSuite
	testIdentity account.Identity
	service      *goa.Service
	invService   invitationservice.InvitationService
	invRepo      invitationrepo.InvitationRepository
}

func (s *TestInvitationREST) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	permService := permissionmodel.NewPermissionModelService(s.DB, s.Application)
	s.invService = invitationmodel.NewInvitationModelService(s.DB, s.Application, permService)
	s.invRepo = invitationrepo.NewInvitationRepository(s.DB)

	var err error
	s.testIdentity, err = testsupport.CreateTestIdentity(s.DB,
		"InvitationCreatorUser-"+uuid.NewV4().String(),
		"TestInvitation")
	require.Nil(s.T(), err)
}

func (s *TestInvitationREST) SecuredController(identity account.Identity) (*goa.Service, *InvitationController) {
	svc := testsupport.ServiceAsUser("Invitation-Service", identity)
	return svc, NewInvitationController(svc, s.invService)
}

func (rest *TestInvitationREST) UnsecuredController() (*goa.Service, *InvitationController) {
	svc := goa.New("Invitation-Service")
	controller := NewInvitationController(svc, rest.invService)
	return svc, controller
}

func TestRunInvitationREST(t *testing.T) {
	suite.Run(t, &TestInvitationREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

/*
* This test will attempt to create a new invitation for a user to become a member of an organization
 */
func (s *TestInvitationREST) TestCreateOrganizationMemberInvitationSuccess() {
	var err error

	orgIdentity, err := testsupport.CreateTestOrganization(s.Ctx, s.DB, s.Application, s.testIdentity.ID, "Acme Corporation"+uuid.NewV4().String())
	require.NoError(s.T(), err, "could not create organization")

	service, controller := s.SecuredController(s.testIdentity)

	testUsername := "jsmith" + uuid.NewV4().String()
	invitee, err := testsupport.CreateTestIdentityAndUser(s.DB, testUsername, "InvitationTest")
	require.NoError(s.T(), err, "could not create invitee user")

	payload := &app.CreateInviteInvitationPayload{
		Data: []*app.Invitee{
			{
				Username: &testUsername,
				Member:   boolPointer(true),
			},
		},
	}

	test.CreateInviteInvitationCreated(s.T(), service.Context, service, controller, orgIdentity.ID.String(), payload)

	invitations, err := s.invRepo.ListForIdentity(s.Ctx, orgIdentity.ID)
	require.NoError(s.T(), err, "could not list invitations")

	// We should have 1 invitation
	require.Equal(s.T(), 1, len(invitations))

	require.Equal(s.T(), invitee.ID, invitations[0].UserID)
	require.True(s.T(), invitations[0].Member)
}

/*
* This test will attempt to create a new invitation for a user to accept a role in an organization
 */
func (s *TestInvitationREST) TestCreateOrganizationRoleInvitationSuccess() {
	var err error

	orgIdentity, err := testsupport.CreateTestOrganization(s.Ctx, s.DB, s.Application, s.testIdentity.ID, "Acme Corporation"+uuid.NewV4().String())
	require.NoError(s.T(), err, "could not create organization")

	service, controller := s.SecuredController(s.testIdentity)

	testUsername := "jsmith" + uuid.NewV4().String()
	invitee, err := testsupport.CreateTestIdentityAndUser(s.DB, testUsername, "InvitationTest")
	require.NoError(s.T(), err, "could not create invitee user")

	payload := &app.CreateInviteInvitationPayload{
		Data: []*app.Invitee{
			{
				Username: &testUsername,
				Member:   boolPointer(false),
				Roles:    []string{"owner"},
			},
		},
	}

	test.CreateInviteInvitationCreated(s.T(), service.Context, service, controller, orgIdentity.ID.String(), payload)

	invitations, err := s.invRepo.ListForIdentity(s.Ctx, orgIdentity.ID)
	require.NoError(s.T(), err, "could not list invitations")

	// We should have 1 invitation
	require.Equal(s.T(), 1, len(invitations))

	require.Equal(s.T(), invitee.ID, invitations[0].UserID)
	require.False(s.T(), invitations[0].Member)

	roles, err := s.invRepo.ListRoles(s.Ctx, invitations[0].InvitationID)
	require.NoError(s.T(), err, "could not list invitation roles")

	// We should have 1 role
	require.Equal(s.T(), 1, len(roles))
	// And it should be the owner role
	require.Equal(s.T(), "owner", roles[0].Name)
}

/*
* This test will attempt to create a new invitation for a user to become a member of an organization, however perform an unauthorized request to create the invitation
 */
func (s *TestInvitationREST) TestCreateOrganizationMemberInvitationUnauthorized() {
	var err error

	orgIdentity, err := testsupport.CreateTestOrganization(s.Ctx, s.DB, s.Application, s.testIdentity.ID, "Acme Corporation"+uuid.NewV4().String())
	require.NoError(s.T(), err, "could not create organization")

	service, controller := s.UnsecuredController()

	testUsername := "jsmith" + uuid.NewV4().String()
	_, err = testsupport.CreateTestIdentityAndUser(s.DB, testUsername, "InvitationTest")
	require.NoError(s.T(), err, "could not create invitee user")

	payload := &app.CreateInviteInvitationPayload{
		Data: []*app.Invitee{
			{
				Username: &testUsername,
				Member:   boolPointer(true),
			},
		},
	}

	test.CreateInviteInvitationUnauthorized(s.T(), service.Context, service, controller, orgIdentity.ID.String(), payload)

	invitations, err := s.invRepo.ListForIdentity(s.Ctx, orgIdentity.ID)
	require.NoError(s.T(), err, "could not list invitations")

	// We should have no invitations
	require.Equal(s.T(), 0, len(invitations))
}

/*
* This test will attempt to create a new invitation for a user to accept an invalid role in an organization,
* we should get a bad request error as a result
 */
func (s *TestInvitationREST) TestCreateOrganizationInvalidRoleInvitation() {
	var err error

	orgIdentity, err := testsupport.CreateTestOrganization(s.Ctx, s.DB, s.Application, s.testIdentity.ID, "Acme Corporation"+uuid.NewV4().String())
	require.NoError(s.T(), err, "could not create organization")

	service, controller := s.SecuredController(s.testIdentity)

	testUsername := "jsmith" + uuid.NewV4().String()
	_, err = testsupport.CreateTestIdentityAndUser(s.DB, testUsername, "InvitationTest")
	require.NoError(s.T(), err, "could not create invitee user")

	payload := &app.CreateInviteInvitationPayload{
		Data: []*app.Invitee{
			{
				Username: &testUsername,
				Member:   boolPointer(false),
				Roles:    []string{"foobar"},
			},
		},
	}

	test.CreateInviteInvitationBadRequest(s.T(), service.Context, service, controller, orgIdentity.ID.String(), payload)

	invitations, err := s.invRepo.ListForIdentity(s.Ctx, orgIdentity.ID)
	require.NoError(s.T(), err, "could not list invitations")

	// We should have no invitations
	require.Equal(s.T(), 0, len(invitations))
}

/*
* This test will attempt to create a new invitation however provide no identifying information for the user
* we should get a bad request error as a result
 */
func (s *TestInvitationREST) TestCreateOrganizationInvalidUserInvitation() {
	var err error

	orgIdentity, err := testsupport.CreateTestOrganization(s.Ctx, s.DB, s.Application, s.testIdentity.ID, "Acme Corporation"+uuid.NewV4().String())
	require.NoError(s.T(), err, "could not create organization")

	service, controller := s.SecuredController(s.testIdentity)

	payload := &app.CreateInviteInvitationPayload{
		Data: []*app.Invitee{
			{
				Member: boolPointer(true),
				Roles:  []string{"foobar"},
			},
		},
	}

	test.CreateInviteInvitationBadRequest(s.T(), service.Context, service, controller, orgIdentity.ID.String(), payload)

	invitations, err := s.invRepo.ListForIdentity(s.Ctx, orgIdentity.ID)
	require.NoError(s.T(), err, "could not list invitations")

	// We should have no invitations
	require.Equal(s.T(), 0, len(invitations))
}

func boolPointer(value bool) *bool {
	return &value
}
