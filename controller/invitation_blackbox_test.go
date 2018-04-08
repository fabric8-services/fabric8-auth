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

func TestRunInvitationREST(t *testing.T) {
	suite.Run(t, &TestInvitationREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

/*
* This test will attempt to create a new invitation
 */
func (s *TestInvitationREST) TestCreateOrganizationMemberInvitationSuccess() {
	var err error

	orgIdentity, err := testsupport.CreateTestOrganization(s.Ctx, s.DB, s.Application, s.testIdentity.ID, "Acme Corporation"+uuid.NewV4().String())
	require.NoError(s.T(), err, "could not create organization")

	service, controller := s.SecuredController(s.testIdentity)

	testUsername := "jsmith" + uuid.NewV4().String()
	invitee, err := testsupport.CreateTestIdentityAndUser(s.DB, testUsername, "InvitationTest")
	require.NoError(s.T(), err, "could not create invitee user")

	payload := &app.CreateGroupInviteInvitationPayload{
		Data: []*app.Invitee{
			{
				Username: &testUsername,
				Member:   true,
			},
		},
	}

	test.CreateGroupInviteInvitationUnauthorized(s.T(), s.Ctx, service, controller, orgIdentity.ID.String(), payload)

	invitations, err := s.invRepo.List(s.Ctx, orgIdentity.ID)
	require.NoError(s.T(), err, "could not list invitations")

	// We should have 1 invitation
	require.Equal(s.T(), 1, len(invitations))

	require.Equal(s.T(), invitee.ID, invitations[0].UserID)
	require.True(s.T(), invitations[0].Member)
}
