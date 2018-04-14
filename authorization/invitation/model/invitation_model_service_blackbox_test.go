package model_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/authorization/invitation"
	invitationModelService "github.com/fabric8-services/fabric8-auth/authorization/invitation/model"
	invitationRepo "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	organizationModelService "github.com/fabric8-services/fabric8-auth/authorization/organization/model"
	permissionModelService "github.com/fabric8-services/fabric8-auth/authorization/permission/model"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/test"

	"github.com/satori/go.uuid"
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
	s.invModelService = invitationModelService.NewInvitationModelService(s.permModelService)
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

	err = s.invModelService.Issue(s.Ctx, s.Application, identity.ID, orgId.String(), invitations)
	require.NoError(s.T(), err, "Error creating invitations")

	invs, err := s.invitationRepo.ListForIdentity(s.Ctx, *orgId)
	require.NoError(s.T(), err, "Error listing invitations")

	require.Equal(s.T(), 1, len(invs))
	require.True(s.T(), invs[0].Member)
}

func (s *invitationModelServiceBlackBoxTest) TestIssueInvitationByUserEmail() {
	// Create a test user - this will be the organization owner
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationModelServiceBlackBoxTest-TestIssuingUser")
	require.NoError(s.T(), err, "Could not create identity")

	// Create an organization
	orgId, err := s.orgModelService.CreateOrganization(s.Ctx, identity.ID, "Test Organization ZZZZZZ")
	require.NoError(s.T(), err, "Could not create organization")

	// Create another test user - we will invite this one to join the organization
	inviteeUser := account.User{
		ID:       uuid.NewV4(),
		Email:    "jsmith-invitationtest" + uuid.NewV4().String() + "@acmecorp.com",
		FullName: "John Smith - Invitation Test",
		Cluster:  "https://api.starter-us-east-2.openshift.com",
	}

	invitee := account.Identity{
		ID:           uuid.NewV4(),
		Username:     "TestInvitee" + uuid.NewV4().String(),
		User:         inviteeUser,
		ProviderType: account.KeycloakIDP,
	}

	err = test.CreateTestIdentityAndUserInDB(s.DB, &invitee)
	require.NoError(s.T(), err, "Error creating invitee user")

	invitations := []invitation.Invitation{
		{
			UserEmail: &inviteeUser.Email,
			Member:    true,
		},
	}

	err = s.invModelService.Issue(s.Ctx, s.Application, identity.ID, orgId.String(), invitations)
	require.NoError(s.T(), err, "Error creating invitations")

	invs, err := s.invitationRepo.ListForIdentity(s.Ctx, *orgId)
	require.NoError(s.T(), err, "Error listing invitations")

	require.Equal(s.T(), 1, len(invs))
	require.Equal(s.T(), invitee.ID, invs[0].IdentityID)
	require.True(s.T(), invs[0].Member)
}

func (s *invitationModelServiceBlackBoxTest) TestIssueInvitationByUserName() {
	// Create a test user - this will be the organization owner
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationModelServiceBlackBoxTest-TestIssuingUser")
	require.NoError(s.T(), err, "Could not create identity")

	// Create an organization
	orgId, err := s.orgModelService.CreateOrganization(s.Ctx, identity.ID, "Test Organization ZZZZZZ")
	require.NoError(s.T(), err, "Could not create organization")

	// Create another test user - we will invite this one to join the organization
	invitee, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationModelServiceBlackBoxTest-TestInviteeUser-"+uuid.NewV4().String())
	require.NoError(s.T(), err, "Could not create identity")

	invitations := []invitation.Invitation{
		{
			UserName: &invitee.Username,
			Member:   true,
		},
	}

	err = s.invModelService.Issue(s.Ctx, s.Application, identity.ID, orgId.String(), invitations)
	require.NoError(s.T(), err, "Error creating invitations")

	invs, err := s.invitationRepo.ListForIdentity(s.Ctx, *orgId)
	require.NoError(s.T(), err, "Error listing invitations")

	require.Equal(s.T(), 1, len(invs))
	require.Equal(s.T(), invitee.ID, invs[0].IdentityID)
	require.True(s.T(), invs[0].Member)
}

func (s *invitationModelServiceBlackBoxTest) TestIssueMultipleInvitations() {
	// Create a test user - this will be the organization owner
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationModelServiceBlackBoxTest-TestIssuingUser")
	require.NoError(s.T(), err, "Could not create identity")

	// Create an organization
	orgId, err := s.orgModelService.CreateOrganization(s.Ctx, identity.ID, "Test Organization ZZZZZZ")
	require.NoError(s.T(), err, "Could not create organization")

	// Create another test user - we will invite this one to join the organization
	invitee, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationModelServiceBlackBoxTest-TestInviteeUser-"+uuid.NewV4().String())
	require.NoError(s.T(), err, "Could not create identity")

	// Create another test user - we will invite this one to join the organization
	invitee2User := account.User{
		ID:       uuid.NewV4(),
		Email:    "jsmith-invitationtest" + uuid.NewV4().String() + "@acmecorp.com",
		FullName: "John Smith - Invitation Test",
		Cluster:  "https://api.starter-us-east-2.openshift.com",
	}

	invitee2 := account.Identity{
		ID:           uuid.NewV4(),
		Username:     "TestInvitee" + uuid.NewV4().String(),
		User:         invitee2User,
		ProviderType: account.KeycloakIDP,
	}

	err = test.CreateTestIdentityAndUserInDB(s.DB, &invitee2)
	require.NoError(s.T(), err, "Error creating invitee2 user")

	invitations := []invitation.Invitation{
		{
			UserName: &invitee.Username,
			Member:   true,
		},
		{
			UserEmail: &invitee2User.Email,
			Member:    true,
		},
	}

	err = s.invModelService.Issue(s.Ctx, s.Application, identity.ID, orgId.String(), invitations)
	require.NoError(s.T(), err, "Error creating invitations")

	invs, err := s.invitationRepo.ListForIdentity(s.Ctx, *orgId)
	require.NoError(s.T(), err, "Error listing invitations")

	require.Equal(s.T(), 2, len(invs))

	found := false

	for _, inv := range invs {
		if inv.IdentityID == invitee.ID {
			found = true
			require.True(s.T(), inv.Member)
		}
	}

	require.True(s.T(), found, "First invitee not found in invitations")

	found = false
	for _, inv := range invs {
		if inv.IdentityID == invitee2.ID {
			found = true
			require.True(s.T(), inv.Member)
		}
	}
	require.True(s.T(), found, "Second invitee not found in invitations")
}

func (s *invitationModelServiceBlackBoxTest) TestIssueInvitationByIdentityIDForRole() {
	// Create a test user - this will be the organization owner
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationModelServiceBlackBoxTest-TestIssuingUser"+uuid.NewV4().String())
	require.Nil(s.T(), err, "Could not create identity")

	// Create an organization
	orgId, err := s.orgModelService.CreateOrganization(s.Ctx, identity.ID, "Test Organization ZZZZZZ")
	require.Nil(s.T(), err, "Could not create organization")

	// Create another test user - we will invite this one to accept the owner role for the organization
	otherIdentity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationModelServiceBlackBoxTest-TestRoleUser")
	require.Nil(s.T(), err, "Could not create other identity")

	ownerRole := "owner"

	invitations := []invitation.Invitation{
		{
			IdentityID: &otherIdentity.ID,
			Roles:      []string{ownerRole},
			Member:     false,
		},
	}

	err = s.invModelService.Issue(s.Ctx, s.Application, identity.ID, orgId.String(), invitations)
	require.NoError(s.T(), err, "Error creating invitations")

	invs, err := s.invitationRepo.ListForIdentity(s.Ctx, *orgId)
	require.NoError(s.T(), err, "Error listing invitations")

	require.Equal(s.T(), 1, len(invs))
	require.False(s.T(), invs[0].Member)

	roles, err := s.invitationRepo.ListRoles(s.Ctx, invs[0].InvitationID)
	require.NoError(s.T(), err, "could not list roles")

	require.Equal(s.T(), 1, len(roles))
	require.Equal(s.T(), "owner", roles[0].Name)
}
