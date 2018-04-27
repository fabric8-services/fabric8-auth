package service_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/authorization/invitation"
	invitationrepo "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	invitationservice "github.com/fabric8-services/fabric8-auth/authorization/invitation/service"
	organizationservice "github.com/fabric8-services/fabric8-auth/authorization/organization/service"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/test"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type invitationServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	invitationRepo invitationrepo.InvitationRepository
	identityRepo   account.IdentityRepository
	invService     invitationservice.InvitationService
	orgService     organizationservice.OrganizationService
}

func TestRunInvitationServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &invitationServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *invitationServiceBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.invitationRepo = invitationrepo.NewInvitationRepository(s.DB)
	s.invService = invitationservice.NewInvitationService(s.Application)
	s.identityRepo = account.NewIdentityRepository(s.DB)
	s.orgService = organizationservice.NewOrganizationService(s.Application, s.Application)
}

func (s *invitationServiceBlackBoxTest) TestIssueInvitationByIdentityID() {
	// Create a test user - this will be the organization owner
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestIssuingUser")
	require.Nil(s.T(), err, "Could not create identity")

	// Create an organization
	orgId, err := s.orgService.CreateOrganization(s.Ctx, identity.ID, "Test Organization ZZZZZZ")
	require.Nil(s.T(), err, "Could not create organization")

	// Create another test user - we will invite this one to join the organization
	otherIdentity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestInviteeUser")
	require.Nil(s.T(), err, "Could not create other identity")

	invitations := []invitation.Invitation{
		{
			IdentityID: &otherIdentity.ID,
			Member:     true,
		},
	}

	err = s.invService.Issue(s.Ctx, identity.ID, orgId.String(), invitations)
	require.NoError(s.T(), err, "Error creating invitations")

	invs, err := s.invitationRepo.ListForIdentity(s.Ctx, *orgId)
	require.NoError(s.T(), err, "Error listing invitations")

	require.Equal(s.T(), 1, len(invs))
	require.True(s.T(), invs[0].Member)
}

func (s *invitationServiceBlackBoxTest) TestIssueInvitationFailsForInvalidID() {
	// Create a test user - this will be the inviter
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestIssuingUser")
	require.Nil(s.T(), err, "Could not create identity")

	// Create another test user - we will invite this one to join the nonexistent "thing"
	otherIdentity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestInviteeUser")
	require.Nil(s.T(), err, "Could not create other identity")

	invitations := []invitation.Invitation{
		{
			IdentityID: &otherIdentity.ID,
			Member:     true,
		},
	}

	err = s.invService.Issue(s.Ctx, identity.ID, uuid.Must(uuid.NewV4()).String(), invitations)
	require.Error(s.T(), err)

	err = s.invService.Issue(s.Ctx, identity.ID, "foo", invitations)
	require.Error(s.T(), err)
}

func (s *invitationServiceBlackBoxTest) TestIssueInvitationOKForResource() {
	// Create a test user - this will be the inviter
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestIssuingUser")
	require.NoError(s.T(), err)

	// Create another test user - we will invite this one to accept a role for the resource
	otherIdentity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestInviteeUser")
	require.NoError(s.T(), err)

	// Create a new resource type
	resourceType, err := test.CreateTestResourceType(s.Ctx, s.DB, "invitation.test/space")
	require.NoError(s.T(), err)

	// Create the manage members scope for the new resource type
	scope, err := test.CreateTestScope(s.Ctx, s.DB, *resourceType, authorization.ManageMembersScope)
	require.NoError(s.T(), err)

	// Create an owner role for the resource type
	role, err := test.CreateTestRole(s.Ctx, s.DB, *resourceType, authorization.OwnerRole)
	require.NoError(s.T(), err)

	// Assign the scope to our role
	_, err = test.CreateTestRoleScope(s.Ctx, s.DB, *scope, *role)
	require.NoError(s.T(), err)

	// Create a resource
	resource, err := test.CreateTestResource(s.Ctx, s.DB, *resourceType, "InvitationTestResource", nil)
	require.NoError(s.T(), err)

	// Assign the owner role to our user for the resource
	test.CreateTestIdentityRoleForIdentity(s.Ctx, s.DB, identity, *resource, *role)
	require.NoError(s.T(), err)

	// Create an invitation
	invitations := []invitation.Invitation{
		{
			IdentityID: &otherIdentity.ID,
			Roles:      []string{authorization.OwnerRole},
		},
	}

	// Issue the invitation
	err = s.invService.Issue(s.Ctx, identity.ID, resource.ResourceID, invitations)
	require.NoError(s.T(), err)

	// List the invitations for our resource
	invs, err := s.invitationRepo.ListForResource(s.Ctx, resource.ResourceID)
	require.NoError(s.T(), err, "Error listing invitations")

	// There should be 1 invitation only
	require.Equal(s.T(), 1, len(invs))
	require.False(s.T(), invs[0].Member)
	require.Equal(s.T(), otherIdentity.ID, invs[0].IdentityID)

	// List the roles for our invitation
	roles, err := s.invitationRepo.ListRoles(s.Ctx, invs[0].InvitationID)
	require.NoError(s.T(), err, "Error listing roles")

	// There should be 1 role only
	require.Equal(s.T(), 1, len(roles))
	require.Equal(s.T(), authorization.OwnerRole, roles[0].Name)
}

func (s *invitationServiceBlackBoxTest) TestIssueMemberInvitationFailsForResource() {
	// Create a test user - this will be the inviter
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestIssuingUser")
	require.NoError(s.T(), err)

	// Create another test user - we will invite this one to accept a role for the resource
	otherIdentity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestInviteeUser")
	require.NoError(s.T(), err)

	// Create a new resource type
	resourceType, err := test.CreateTestResourceType(s.Ctx, s.DB, "invitation.test/foo")
	require.NoError(s.T(), err)

	// Create the manage members scope for the new resource type
	scope, err := test.CreateTestScope(s.Ctx, s.DB, *resourceType, authorization.ManageMembersScope)
	require.NoError(s.T(), err)

	// Create an owner role for the resource type
	role, err := test.CreateTestRole(s.Ctx, s.DB, *resourceType, authorization.OwnerRole)
	require.NoError(s.T(), err)

	// Assign the scope to our role
	_, err = test.CreateTestRoleScope(s.Ctx, s.DB, *scope, *role)
	require.NoError(s.T(), err)

	// Create a resource
	resource, err := test.CreateTestResource(s.Ctx, s.DB, *resourceType, "InvitationTestResourceFoo", nil)
	require.NoError(s.T(), err)

	// Assign the owner role to our user for the resource
	test.CreateTestIdentityRoleForIdentity(s.Ctx, s.DB, identity, *resource, *role)
	require.NoError(s.T(), err)

	// Create an invitation
	invitations := []invitation.Invitation{
		{
			IdentityID: &otherIdentity.ID,
			Member:     true,
		},
	}

	// Issue the invitation, which should fail because the new resource can't have members
	err = s.invService.Issue(s.Ctx, identity.ID, resource.ResourceID, invitations)
	require.Error(s.T(), err)
}

func (s *invitationServiceBlackBoxTest) TestIssueUnprivilegedInvitationFailsForResource() {
	// Create a test user - this will be the inviter
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestIssuingUser")
	require.NoError(s.T(), err)

	// Create another test user - we will invite this one to accept a role for the resource
	otherIdentity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestInviteeUser")
	require.NoError(s.T(), err)

	// Create a new resource type
	resourceType, err := test.CreateTestResourceType(s.Ctx, s.DB, "invitation.test/foo")
	require.NoError(s.T(), err)

	// Create an owner role for the resource type
	_, err = test.CreateTestRole(s.Ctx, s.DB, *resourceType, authorization.OwnerRole)
	require.NoError(s.T(), err)

	// Create a resource
	resource, err := test.CreateTestResource(s.Ctx, s.DB, *resourceType, "InvitationTestResourceFoo", nil)
	require.NoError(s.T(), err)

	// Create an invitation
	invitations := []invitation.Invitation{
		{
			IdentityID: &otherIdentity.ID,
			Roles:      []string{authorization.OwnerRole},
		},
	}

	// Issue the invitation, which should fail because the inviter has insufficient privileges to issue an invitation
	err = s.invService.Issue(s.Ctx, identity.ID, resource.ResourceID, invitations)
	require.Error(s.T(), err)
}

func (s *invitationServiceBlackBoxTest) TestIssueInvitationFailsForNonOwner() {
	// Create a test user - this will be the owner
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestIssuingUser")
	require.Nil(s.T(), err, "Could not create identity")

	// Create an organization
	orgId, err := s.orgService.CreateOrganization(s.Ctx, identity.ID, "Test Organization ZZZZZZ")
	require.Nil(s.T(), err, "Could not create organization")

	// Create another test user - we will attempt to have this user invite themselves to the organization
	otherIdentity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestInviteeUser")
	require.Nil(s.T(), err, "Could not create other identity")

	invitations := []invitation.Invitation{
		{
			IdentityID: &otherIdentity.ID,
			Member:     true,
		},
	}

	err = s.invService.Issue(s.Ctx, otherIdentity.ID, orgId.String(), invitations)
	require.Error(s.T(), err)
}

func (s *invitationServiceBlackBoxTest) TestIssueInvitationFailsForUnknownUser() {
	// Create a test user - this will be the organization owner
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestIssuingUser")
	require.Nil(s.T(), err, "Could not create identity")

	// Create an organization
	orgId, err := s.orgService.CreateOrganization(s.Ctx, identity.ID, "Test Organization ZZZZZZ")
	require.Nil(s.T(), err, "Could not create organization")

	invalidIdentityID := uuid.Must(uuid.NewV4())

	invitations := []invitation.Invitation{
		{
			IdentityID: &invalidIdentityID,
			Member:     true,
		},
	}

	// This should fail because we specified an unknown identity ID
	err = s.invService.Issue(s.Ctx, identity.ID, orgId.String(), invitations)
	require.Error(s.T(), err)
}

func (s *invitationServiceBlackBoxTest) TestIssueInvitationFailsForNonUser() {
	// Create a test user - this will be the organization owner
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestIssuingUser")
	require.Nil(s.T(), err, "Could not create identity")

	// Create an organization, we're going to do something crazy and invite the organization to join itself
	orgId, err := s.orgService.CreateOrganization(s.Ctx, identity.ID, "Test Organization ZZZZZZ")
	require.Nil(s.T(), err, "Could not create organization")

	invitations := []invitation.Invitation{
		{
			IdentityID: orgId,
			Member:     true,
		},
	}

	// This should fail because we specified a non-user identity in the invitation
	err = s.invService.Issue(s.Ctx, identity.ID, orgId.String(), invitations)
	require.Error(s.T(), err)
}

func (s *invitationServiceBlackBoxTest) TestIssueInvitationFailsForNonMembershipIdentity() {
	// Create a test user - this will be the inviter, and the identity to which the other identity will be invited
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestIssuingUser")
	require.Nil(s.T(), err, "Could not create identity")

	// Create an invitee
	otherIdentity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestInviteeUser")
	require.Nil(s.T(), err, "Could not create other identity")

	invitations := []invitation.Invitation{
		{
			IdentityID: &otherIdentity.ID,
			Member:     true,
		},
	}

	// Invite the user to "join" the other user as a member, this should fail
	err = s.invService.Issue(s.Ctx, identity.ID, identity.ID.String(), invitations)
	require.Error(s.T(), err)
}

func (s *invitationServiceBlackBoxTest) TestIssueMultipleInvitations() {
	// Create a test user - this will be the organization owner
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestIssuingUser")
	require.NoError(s.T(), err, "Could not create identity")

	// Create an organization
	orgId, err := s.orgService.CreateOrganization(s.Ctx, identity.ID, "Test Organization ZZZZZZ")
	require.NoError(s.T(), err, "Could not create organization")

	// Create another test user - we will invite this one to join the organization
	invitee, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestInviteeUser-"+uuid.Must(uuid.NewV4()).String())
	require.NoError(s.T(), err, "Could not create identity")

	// Create another test user - we will invite this one to join the organization
	invitee2User := account.User{
		ID:       uuid.Must(uuid.NewV4()),
		Email:    "jsmith-invitationtest" + uuid.Must(uuid.NewV4()).String() + "@acmecorp.com",
		FullName: "John Smith - Invitation Test",
		Cluster:  "https://api.starter-us-east-2.openshift.com",
	}

	invitee2 := account.Identity{
		ID:           uuid.Must(uuid.NewV4()),
		Username:     "TestInvitee" + uuid.Must(uuid.NewV4()).String(),
		User:         invitee2User,
		ProviderType: account.KeycloakIDP,
	}

	err = test.CreateTestIdentityAndUserInDB(s.DB, &invitee2)
	require.NoError(s.T(), err, "Error creating invitee2 user")

	invitations := []invitation.Invitation{
		{
			IdentityID: &invitee.ID,
			Member:     true,
		},
		{
			IdentityID: &invitee2.ID,
			Member:     true,
		},
	}

	err = s.invService.Issue(s.Ctx, identity.ID, orgId.String(), invitations)
	require.NoError(s.T(), err, "Error creating invitations")

	invs, err := s.invitationRepo.ListForIdentity(s.Ctx, *orgId)
	require.NoError(s.T(), err, "Error listing invitations")

	require.Equal(s.T(), 2, len(invs))

	found := false

	for _, inv := range invs {
		if inv.IdentityID == invitee.ID {
			found = true
			require.True(s.T(), inv.Member)
			require.Equal(s.T(), invitee.ID, inv.IdentityID)
			require.Equal(s.T(), orgId, inv.InviteTo)
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

func (s *invitationServiceBlackBoxTest) TestIssueInvitationByIdentityIDForRole() {
	// Create a test user - this will be the organization owner
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestIssuingUser"+uuid.Must(uuid.NewV4()).String())
	require.Nil(s.T(), err, "Could not create identity")

	// Create an organization
	orgId, err := s.orgService.CreateOrganization(s.Ctx, identity.ID, "Test Organization ZZZZZZ")
	require.Nil(s.T(), err, "Could not create organization")

	// Create another test user - we will invite this one to accept the owner role for the organization
	otherIdentity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestRoleUser")
	require.Nil(s.T(), err, "Could not create other identity")

	ownerRole := "owner"

	invitations := []invitation.Invitation{
		{
			IdentityID: &otherIdentity.ID,
			Roles:      []string{ownerRole},
			Member:     false,
		},
	}

	err = s.invService.Issue(s.Ctx, identity.ID, orgId.String(), invitations)
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
