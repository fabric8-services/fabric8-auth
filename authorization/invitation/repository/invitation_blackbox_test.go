package repository_test

import (
	"testing"

	invitation "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	roleRepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type invitationBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo invitation.InvitationRepository
}

func TestRunInvitationBlackBoxTest(t *testing.T) {
	suite.Run(t, &invitationBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *invitationBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.DB.LogMode(true)
	s.repo = invitation.NewInvitationRepository(s.DB)
}

func (s *invitationBlackBoxTest) TestOKToDelete() {
	invitation, err := s.CreateTestInvitation()
	require.NoError(s.T(), err)

	invitations, err := s.repo.List(s.Ctx, invitation.InviteToID)
	require.NoError(s.T(), err)
	require.Equal(s.T(), 1, len(invitations))

	err = s.repo.Delete(s.Ctx, invitation.InvitationID)
	require.NoError(s.T(), err)

	invitations, err = s.repo.List(s.Ctx, invitation.InviteToID)
	require.NoError(s.T(), err)
	require.Equal(s.T(), 0, len(invitations))
}

func (s *invitationBlackBoxTest) TestOKToLoad() {
	invitation, err := s.CreateTestInvitation()
	require.NoError(s.T(), err)

	_, err = s.repo.Load(s.Ctx, invitation.InvitationID)
	require.NoError(s.T(), err)
}

func (s *invitationBlackBoxTest) TestExistsInvitation() {
	invitation, err := s.CreateTestInvitation()
	require.NoError(s.T(), err)

	exists, err := s.repo.CheckExists(s.Ctx, invitation.InvitationID)
	require.NoError(s.T(), err)
	require.True(s.T(), exists)
}

func (s *invitationBlackBoxTest) TestOKToSave() {
	invitation, err := s.CreateTestInvitation()
	require.NoError(s.T(), err)

	_, err = s.repo.Load(s.Ctx, invitation.InvitationID)
	require.NoError(s.T(), err)

	require.False(s.T(), invitation.Member)

	invitation.Member = true
	err = s.repo.Save(s.Ctx, &invitation)
	require.NoError(s.T(), err)

	require.True(s.T(), invitation.Member)
}

func (s *invitationBlackBoxTest) TestAddRole() {
	invitation, err := s.CreateTestInvitation()
	require.NoError(s.T(), err)

	roleRepository := roleRepo.NewRoleRepository(s.DB)
	role, err := roleRepository.Lookup(s.Ctx, authorization.OwnerRole, authorization.IdentityResourceTypeOrganization)
	require.NoError(s.T(), err)

	err = s.repo.AddRole(s.Ctx, invitation.InvitationID, role.RoleID)
	require.NoError(s.T(), err)
}

func (s *invitationBlackBoxTest) TestListRoles() {
	invitation, err := s.CreateTestInvitation()
	require.NoError(s.T(), err)

	roleRepository := roleRepo.NewRoleRepository(s.DB)
	role, err := roleRepository.Lookup(s.Ctx, authorization.OwnerRole, authorization.IdentityResourceTypeOrganization)
	require.NoError(s.T(), err)

	err = s.repo.AddRole(s.Ctx, invitation.InvitationID, role.RoleID)
	require.NoError(s.T(), err)

	roles, err := s.repo.ListRoles(s.Ctx, invitation.InvitationID)
	require.NoError(s.T(), err)

	require.Equal(s.T(), 1, len(roles))
	require.Equal(s.T(), authorization.OwnerRole, roles[0].Name)
}

func (s *invitationBlackBoxTest) CreateTestInvitation() (invitation.Invitation, error) {
	var invitation invitation.Invitation

	orgIdentity, err := testsupport.CreateTestOrganizationIdentity(s.DB)
	if err != nil {
		return invitation, err
	}

	userIdentity, err := testsupport.CreateTestUser(s.DB, &testsupport.TestUser)
	if err != nil {
		return invitation, err
	}

	invitation = invitation.Invitation{
		InviteToID: orgIdentity.ID,
		UserID:     userIdentity.ID,
		Member:     false,
	}

	err = s.repo.Create(s.Ctx, &invitation)
	return invitation, nil
}
