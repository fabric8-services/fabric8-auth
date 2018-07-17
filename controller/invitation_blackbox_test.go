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

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/authorization"
	invitationrepo "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"net/url"
)

type TestInvitationREST struct {
	gormtestsupport.DBTestSuite
	testIdentity account.Identity
	service      *goa.Service
	invService   service.InvitationService
	invRepo      invitationrepo.InvitationRepository
}

func (s *TestInvitationREST) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.invService = s.Application.InvitationService()
	s.invRepo = invitationrepo.NewInvitationRepository(s.DB)

	var err error
	s.testIdentity, err = testsupport.CreateTestIdentity(s.DB,
		"InvitationCreatorUser-"+uuid.NewV4().String(),
		"TestInvitation")
	require.Nil(s.T(), err)
}

func (s *TestInvitationREST) SecuredController(identity account.Identity) (*goa.Service, *InvitationController) {
	svc := testsupport.ServiceAsUser("Invitation-Service", identity)
	return svc, NewInvitationController(svc, s.Application, s.Configuration)
}

func (s *TestInvitationREST) UnsecuredController() (*goa.Service, *InvitationController) {
	svc := goa.New("Invitation-Service")
	controller := NewInvitationController(svc, s.Application, s.Configuration)
	return svc, controller
}

func TestRunInvitationREST(t *testing.T) {
	suite.Run(t, &TestInvitationREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

/*
* This test will attempt to create a new invitation for a user to become a member of an organization
 */
func (s *TestInvitationREST) TestCreateTeamMemberInvitationSuccess() {
	var err error

	g := s.NewTestGraph()
	team := g.CreateTeam()

	r := g.CreateRole(g.LoadResourceType(authorization.IdentityResourceTypeTeam))
	r.AddScope(authorization.ManageTeamMembersScope)
	team.AssignRole(&s.testIdentity, r.Role())

	service, controller := s.SecuredController(s.testIdentity)

	invitee := g.CreateUser()
	inviteeID := invitee.IdentityID().String()

	payload := &app.CreateInviteInvitationPayload{
		Data: []*app.Invitee{
			{
				IdentityID: &inviteeID,
				Member:     boolPointer(true),
			},
		},
	}

	test.CreateInviteInvitationCreated(s.T(), service.Context, service, controller, team.TeamID().String(), payload)

	invitations, err := s.invRepo.ListForIdentity(s.Ctx, team.TeamID())
	require.NoError(s.T(), err, "could not list invitations")

	// We should have 1 invitation
	require.Equal(s.T(), 1, len(invitations))

	require.Equal(s.T(), invitee.IdentityID(), invitations[0].IdentityID)
	require.True(s.T(), invitations[0].Member)
}

/*
* This test will attempt to create a new invitation for a user to accept a role in an organization
 */
func (s *TestInvitationREST) TestCreateTeamRoleInvitationSuccess() {
	var err error

	g := s.NewTestGraph()
	team := g.CreateTeam()

	r := g.CreateRole(g.LoadResourceType(authorization.IdentityResourceTypeTeam))
	r.AddScope(authorization.ManageTeamMembersScope)
	team.AssignRole(&s.testIdentity, r.Role())

	service, controller := s.SecuredController(s.testIdentity)

	invitee := g.CreateUser()
	inviteeID := invitee.IdentityID().String()

	payload := &app.CreateInviteInvitationPayload{
		Data: []*app.Invitee{
			{
				IdentityID: &inviteeID,
				Member:     boolPointer(false),
				Roles:      []string{r.Role().Name},
			},
		},
	}

	test.CreateInviteInvitationCreated(s.T(), service.Context, service, controller, team.TeamID().String(), payload)

	invitations, err := s.invRepo.ListForIdentity(s.Ctx, team.TeamID())
	require.NoError(s.T(), err, "could not list invitations")

	// We should have 1 invitation
	require.Equal(s.T(), 1, len(invitations))

	require.Equal(s.T(), invitee.IdentityID(), invitations[0].IdentityID)
	require.False(s.T(), invitations[0].Member)

	roles, err := s.invRepo.ListRoles(s.Ctx, invitations[0].InvitationID)
	require.NoError(s.T(), err, "could not list invitation roles")

	// We should have 1 role
	require.Equal(s.T(), 1, len(roles))
	// And it should be the owner role
	require.Equal(s.T(), r.Role().Name, roles[0].Name)
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
	invitee, err := testsupport.CreateTestIdentityAndUser(s.DB, testUsername, "InvitationTest")
	require.NoError(s.T(), err, "could not create invitee user")

	inviteeID := invitee.ID.String()

	payload := &app.CreateInviteInvitationPayload{
		Data: []*app.Invitee{
			{
				IdentityID: &inviteeID,
				Member:     boolPointer(true),
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
	invitee, err := testsupport.CreateTestIdentityAndUser(s.DB, testUsername, "InvitationTest")
	require.NoError(s.T(), err, "could not create invitee user")

	inviteeID := invitee.ID.String()

	payload := &app.CreateInviteInvitationPayload{
		Data: []*app.Invitee{
			{
				IdentityID: &inviteeID,
				Member:     boolPointer(false),
				Roles:      []string{"foobar"},
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

func (s *TestInvitationREST) TestAcceptInvitation() {
	g := s.NewTestGraph()
	team := g.CreateTeam()
	invitee := g.CreateUser()
	inv := g.CreateInvitation(team, invitee)

	service, controller := s.SecuredController(s.testIdentity)

	response := test.AcceptInviteInvitationTemporaryRedirect(s.T(), service.Context, service, controller, inv.Invitation().AcceptCode.String())

	require.NotNil(s.T(), response.Header().Get("Location"))

	// The invitation should no longer be there after acceptance
	_, err := s.Application.InvitationRepository().FindByAcceptCode(s.Ctx, s.testIdentity.ID, inv.Invitation().AcceptCode)
	require.Error(s.T(), err)
	require.IsType(s.T(), errors.NotFoundError{}, err)
}

func (s *TestInvitationREST) TestAcceptInvitationFailsForInvalidCode() {
	service, controller := s.SecuredController(s.testIdentity)

	// This should still work, however there should now be an error param in the redirect URL
	response := test.AcceptInviteInvitationTemporaryRedirect(s.T(), service.Context, service, controller, uuid.NewV4().String())
	require.NotNil(s.T(), response.Header().Get("Location"))

	parsedURL, err := url.Parse(response.Header().Get("Location"))
	require.NoError(s.T(), err)
	parameters := parsedURL.Query()
	require.NotNil(s.T(), parameters.Get("error"))
}

func (s *TestInvitationREST) TestAcceptInvitationFailsForNonUUIDCode() {
	g := s.NewTestGraph()
	team := g.CreateTeam()
	invitee := g.CreateUser()
	g.CreateInvitation(team, invitee)

	service, controller := s.SecuredController(s.testIdentity)

	response := test.AcceptInviteInvitationTemporaryRedirect(s.T(), service.Context, service, controller, "foo")
	parsedURL, err := url.Parse(response.Header().Get("Location"))
	require.NoError(s.T(), err)
	parameters := parsedURL.Query()
	require.NotNil(s.T(), parameters.Get("error"))
}

func boolPointer(value bool) *bool {
	return &value
}
