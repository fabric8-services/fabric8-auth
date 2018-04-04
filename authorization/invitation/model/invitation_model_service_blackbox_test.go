package model_test

import (
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/authorization/invitation"
	invitationModelService "github.com/fabric8-services/fabric8-auth/authorization/invitation/model"
	invitationRepo "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	organizationModelService "github.com/fabric8-services/fabric8-auth/authorization/organization/model"
	permissionModelService "github.com/fabric8-services/fabric8-auth/authorization/permission/model"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/test"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type invitationModelServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	invitationRepo   invitationRepo.InvitationRepository
	identityRepo     account.IdentityRepository
	invModelService  invitationModelService.InvitationModelService
	orgModelService  organizationModelService.OrganizationModelService
	permModelService permissionModelService.PermissionModelService
}

func TestRunInvitationModelServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &invitationModelServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *invitationModelServiceBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.invitationRepo = invitationRepo.NewInvitationRepository(s.DB)
	s.permModelService = permissionModelService.NewPermissionModelService(s.DB, s.Application)
	s.invModelService = invitationModelService.NewInvitationModelService(s.DB, s.Application, s.permModelService)
	s.identityRepo = account.NewIdentityRepository(s.DB)
	s.orgModelService = organizationModelService.NewOrganizationModelService(s.DB, s.Application)
}

func (s *invitationModelServiceBlackBoxTest) TestIssueInvitationByIdentityID() {
	// Create a test user - this will be the organization owner
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationModelServiceBlackBoxTest-TestIssuingUser")
	require.Nil(s.T(), err, "Could not create identity")

	// Create an organization
	orgId, err := s.orgModelService.CreateOrganization(s.Ctx, identity.ID, "Test Organization ZZZZZZ")
	require.Nil(s.T(), err, "Could not create organization")

	// Create another test user - we will invite this one to join the organization
	otherIdentity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationModelServiceBlackBoxTest-TestInviteeUser")
	require.Nil(s.T(), err, "Could not create other identity")

	invitations := []invitation.Invitation{
		{
			IdentityID: &otherIdentity.ID,
			Member:     true,
		},
	}

	err = s.invModelService.CreateInvitations(s.Ctx, identity.ID, *orgId, invitations)
	require.NoError(s.T(), err, "Error creating invitations")

	invs, err := s.invitationRepo.List(s.Ctx, *orgId)
	require.NoError(s.T(), err, "Error listing invitations")

	require.Equal(s.T(), 1, len(invs))
}
