package service_test

import (
	"testing"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/authorization/invitation"
	invitationrepo "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
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
	orgService     service.OrganizationService
	witURL         string
}

func TestRunInvitationServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &invitationServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *invitationServiceBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.invitationRepo = invitationrepo.NewInvitationRepository(s.DB)
	s.identityRepo = account.NewIdentityRepository(s.DB)
	s.orgService = s.Application.OrganizationService()
}

func (s *invitationServiceBlackBoxTest) TestIssueInvitationByIdentityID() {
	g := s.NewTestGraph()

	// Create a test user - this will be the team admin
	teamAdmin := g.CreateUser()

	// Create a team
	team := g.CreateTeam()

	// Create an admin role and assign it to the team admin
	r := g.CreateRole(g.LoadResourceType(authorization.IdentityResourceTypeTeam))
	r.AddScope(authorization.ManageTeamMembersScope)

	team.AssignRole(teamAdmin.Identity(), r.Role())

	// Create another test user - we will invite this one to join the team
	invitee := g.CreateUser()
	id := invitee.IdentityID()

	invitations := []invitation.Invitation{
		{
			IdentityID: &id,
			Member:     true,
		},
	}

	err := s.Application.InvitationService().Issue(s.Ctx, teamAdmin.IdentityID(), team.TeamID().String(), invitations)
	require.NoError(s.T(), err, "Error creating invitations")

	invs, err := s.invitationRepo.ListForIdentity(s.Ctx, team.TeamID())
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

	err = s.Application.InvitationService().Issue(s.Ctx, identity.ID, uuid.NewV4().String(), invitations)
	require.Error(s.T(), err)

	err = s.Application.InvitationService().Issue(s.Ctx, identity.ID, "foo", invitations)
	require.Error(s.T(), err)
}

func (s *invitationServiceBlackBoxTest) TestIssueInvitationOKForResource() {
	g := s.NewTestGraph()

	// Create a test user - this will be the inviter
	inviter := g.CreateUser()

	// Create another test user - we will invite this one to accept a role for the resource
	invitee := g.CreateUser()
	inviteeID := invitee.IdentityID()

	space := g.CreateSpace()
	space.AddAdmin(inviter)

	// Create an invitation
	invitations := []invitation.Invitation{
		{
			IdentityID: &inviteeID,
			Roles:      []string{"admin"},
		},
	}

	// Issue the invitation
	err := s.Application.InvitationService().Issue(s.Ctx, inviter.IdentityID(), space.SpaceID(), invitations)
	require.NoError(s.T(), err)

	// List the invitations for our resource
	invs, err := s.invitationRepo.ListForResource(s.Ctx, space.SpaceID())
	require.NoError(s.T(), err, "Error listing invitations")

	// There should be 1 invitation only
	require.Equal(s.T(), 1, len(invs))
	require.False(s.T(), invs[0].Member)
	require.Equal(s.T(), invitee.IdentityID(), invs[0].IdentityID)

	// List the roles for our invitation
	roles, err := s.invitationRepo.ListRoles(s.Ctx, invs[0].InvitationID)
	require.NoError(s.T(), err, "Error listing roles")

	// There should be 1 role only
	require.Equal(s.T(), 1, len(roles))
	require.Equal(s.T(), "admin", roles[0].Name)
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

	// Create the manage members scope for the new resource type (we will use the same scope as for organizations)
	scope, err := test.CreateTestScope(s.Ctx, s.DB, *resourceType, authorization.ManageOrganizationMembersScope)
	require.NoError(s.T(), err)

	// Create an admin role for the resource type
	role, err := test.CreateTestRole(s.Ctx, s.DB, *resourceType, "admin")
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
	err = s.Application.InvitationService().Issue(s.Ctx, identity.ID, resource.ResourceID, invitations)
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

	// Create an admin role for the resource type
	_, err = test.CreateTestRole(s.Ctx, s.DB, *resourceType, "admin")
	require.NoError(s.T(), err)

	// Create a resource
	resource, err := test.CreateTestResource(s.Ctx, s.DB, *resourceType, "InvitationTestResourceFoo", nil)
	require.NoError(s.T(), err)

	// Create an invitation
	invitations := []invitation.Invitation{
		{
			IdentityID: &otherIdentity.ID,
			Roles:      []string{"admin"},
		},
	}

	// Issue the invitation, which should fail because the inviter has insufficient privileges to issue an invitation
	err = s.Application.InvitationService().Issue(s.Ctx, identity.ID, resource.ResourceID, invitations)
	require.Error(s.T(), err)
}

func (s *invitationServiceBlackBoxTest) TestIssueInvitationFailsForNonOwner() {
	// Create a test user - this will be the owner
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestIssuingUser")
	require.Nil(s.T(), err, "Could not create identity")

	// Create an organization
	orgId, err := s.orgService.CreateOrganization(s.Ctx, identity.ID, "Test Organization "+uuid.NewV4().String())
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

	err = s.Application.InvitationService().Issue(s.Ctx, otherIdentity.ID, orgId.String(), invitations)
	require.Error(s.T(), err)
}

func (s *invitationServiceBlackBoxTest) TestIssueInvitationFailsForUnknownUser() {
	// Create a test user - this will be the organization owner
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestIssuingUser")
	require.Nil(s.T(), err, "Could not create identity")

	// Create an organization
	orgId, err := s.orgService.CreateOrganization(s.Ctx, identity.ID, "Test Organization "+uuid.NewV4().String())
	require.Nil(s.T(), err, "Could not create organization")

	invalidIdentityID := uuid.NewV4()

	invitations := []invitation.Invitation{
		{
			IdentityID: &invalidIdentityID,
			Member:     true,
		},
	}

	// This should fail because we specified an unknown identity ID
	err = s.Application.InvitationService().Issue(s.Ctx, identity.ID, orgId.String(), invitations)
	require.Error(s.T(), err)
}

func (s *invitationServiceBlackBoxTest) TestIssueInvitationFailsForNonUser() {
	// Create a test user - this will be the organization owner
	identity, err := test.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "invitationServiceBlackBoxTest-TestIssuingUser")
	require.Nil(s.T(), err, "Could not create identity")

	// Create an organization, we're going to do something crazy and invite the organization to join itself
	orgId, err := s.orgService.CreateOrganization(s.Ctx, identity.ID, "Test Organization "+uuid.NewV4().String())
	require.Nil(s.T(), err, "Could not create organization")

	invitations := []invitation.Invitation{
		{
			IdentityID: orgId,
			Member:     true,
		},
	}

	// This should fail because we specified a non-user identity in the invitation
	err = s.Application.InvitationService().Issue(s.Ctx, identity.ID, orgId.String(), invitations)
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
	err = s.Application.InvitationService().Issue(s.Ctx, identity.ID, identity.ID.String(), invitations)
	require.Error(s.T(), err)
}

func (s *invitationServiceBlackBoxTest) TestIssueMultipleInvitations() {
	g := s.NewTestGraph()
	team := g.CreateTeam()
	teamAdmin := g.CreateUser()

	r := g.CreateRole(g.LoadResourceType(authorization.IdentityResourceTypeTeam))
	r.AddScope(authorization.ManageTeamMembersScope)

	team.AssignRole(teamAdmin.Identity(), r.Role())

	invitee1 := g.CreateUser()
	invitee1ID := invitee1.IdentityID()

	invitee2 := g.CreateUser()
	invitee2ID := invitee2.IdentityID()

	invitations := []invitation.Invitation{
		{
			IdentityID: &invitee1ID,
			Member:     true,
		},
		{
			IdentityID: &invitee2ID,
			Member:     true,
		},
	}

	err := s.Application.InvitationService().Issue(s.Ctx, teamAdmin.IdentityID(), team.TeamID().String(), invitations)
	require.NoError(s.T(), err, "Error creating invitations")

	invs, err := s.invitationRepo.ListForIdentity(s.Ctx, team.TeamID())
	require.NoError(s.T(), err, "Error listing invitations")

	require.Equal(s.T(), 2, len(invs))

	found := false

	for _, inv := range invs {
		if inv.IdentityID == invitee1.IdentityID() {
			found = true
			require.True(s.T(), inv.Member)
			require.Equal(s.T(), invitee1.IdentityID(), inv.IdentityID)
			require.Equal(s.T(), team.TeamID(), *inv.InviteTo)
		}
	}

	require.True(s.T(), found, "First invitee not found in invitations")

	found = false
	for _, inv := range invs {
		if inv.IdentityID == invitee2.IdentityID() {
			found = true
			require.True(s.T(), inv.Member)
		}
	}
	require.True(s.T(), found, "Second invitee not found in invitations")
}

func (s *invitationServiceBlackBoxTest) TestIssueInvitationByIdentityIDForRole() {
	g := s.NewTestGraph()
	team := g.CreateTeam()
	teamAdmin := g.CreateUser()
	user := g.CreateUser()
	r := g.CreateRole(g.LoadResourceType(authorization.IdentityResourceTypeTeam))
	r.AddScope(authorization.ManageTeamMembersScope)

	team.AssignRole(teamAdmin.Identity(), r.Role())

	id := user.IdentityID()

	invitations := []invitation.Invitation{
		{
			IdentityID: &id,
			Roles:      []string{r.Role().Name},
			Member:     false,
		},
	}

	err := s.Application.InvitationService().Issue(s.Ctx, teamAdmin.IdentityID(), team.TeamID().String(), invitations)
	require.NoError(s.T(), err, "Error creating invitations")

	invs, err := s.invitationRepo.ListForIdentity(s.Ctx, team.TeamID())
	require.NoError(s.T(), err, "Error listing invitations")

	require.Len(s.T(), invs, 1)
	require.False(s.T(), invs[0].Member)

	roles, err := s.invitationRepo.ListRoles(s.Ctx, invs[0].InvitationID)
	require.NoError(s.T(), err, "could not list roles")

	require.Len(s.T(), roles, 1)
	require.Equal(s.T(), r.Role().Name, roles[0].Name)
}

func (s *invitationServiceBlackBoxTest) TestIssueTeamMemberInvite() {
	g := s.NewTestGraph()
	team := g.CreateTeam()
	teamAdmin := g.CreateUser()
	user := g.CreateUser()
	r := g.CreateRole(g.LoadResourceType(authorization.IdentityResourceTypeTeam))
	r.AddScope(authorization.ManageTeamMembersScope)

	team.AssignRole(teamAdmin.Identity(), r.Role())

	id := user.IdentityID()

	invitations := []invitation.Invitation{
		{
			IdentityID: &id,
			Roles:      nil,
			Member:     true,
		},
	}

	err := s.Application.InvitationService().Issue(s.Ctx, teamAdmin.IdentityID(), team.TeamID().String(), invitations)
	require.NoError(s.T(), err)

	invs, err := s.invitationRepo.ListForIdentity(s.Ctx, team.TeamID())
	require.NoError(s.T(), err)

	require.Len(s.T(), invs, 1)
	require.Equal(s.T(), user.IdentityID(), invs[0].IdentityID)
	require.True(s.T(), invs[0].Member)
}

func (s *invitationServiceBlackBoxTest) TestIssueSpaceInvite() {
	g := s.NewTestGraph()
	space := g.CreateSpace()
	spaceAdmin := g.CreateUser()
	space.AddAdmin(spaceAdmin)

	invitee := g.CreateUser()
	id := invitee.IdentityID()

	r := g.CreateRole("foo", g.LoadResourceType(authorization.ResourceTypeSpace))

	invitations := []invitation.Invitation{
		{
			IdentityID: &id,
			Roles:      []string{r.Role().Name},
		},
	}

	err := s.Application.InvitationService().Issue(s.Ctx, spaceAdmin.IdentityID(), space.SpaceID(), invitations)
	require.NoError(s.T(), err)

	invs, err := s.invitationRepo.ListForResource(s.Ctx, space.SpaceID())
	require.NoError(s.T(), err)

	require.Len(s.T(), invs, 1)
	require.Equal(s.T(), invitee.IdentityID(), invs[0].IdentityID)
	require.False(s.T(), invs[0].Member)
}
