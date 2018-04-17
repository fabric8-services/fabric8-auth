package repository_test

import (
	"testing"

	invitationRepo "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	roleRepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type invitationBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo invitationRepo.InvitationRepository
}

func TestRunInvitationBlackBoxTest(t *testing.T) {
	suite.Run(t, &invitationBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *invitationBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.DB.LogMode(true)
	s.repo = invitationRepo.NewInvitationRepository(s.DB)
}

func (s *invitationBlackBoxTest) TestOKToDelete() {
	invitation, err := s.CreateTestInvitation()
	require.NoError(s.T(), err)

	invitations, err := s.repo.ListForIdentity(s.Ctx, *invitation.InviteTo)
	require.NoError(s.T(), err)
	require.Equal(s.T(), 1, len(invitations))

	err = s.repo.Delete(s.Ctx, invitation.InvitationID)
	require.NoError(s.T(), err)

	invitations, err = s.repo.ListForIdentity(s.Ctx, *invitation.InviteTo)
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
	require.Equal(s.T(), invitation.InviteTo, invitation.InviteTo)
	require.Equal(s.T(), invitation.IdentityID, invitation.IdentityID)
}

func (s *invitationBlackBoxTest) TestCreateFailsForDuplicateKey() {
	invitation, err := s.CreateTestInvitation()
	require.NoError(s.T(), err)

	err = s.repo.Create(s.Ctx, &invitation)
	require.Error(s.T(), err, "create invitation should fail for invitation with duplicate key")
}

func (s *invitationBlackBoxTest) TestSaveFailsForDeletedInvitation() {
	invitation, err := s.CreateTestInvitation()
	require.NoError(s.T(), err)

	err = s.repo.Delete(s.Ctx, invitation.InvitationID)
	require.NoError(s.T(), err)

	err = s.repo.Save(s.Ctx, &invitation)
	require.Error(s.T(), err, "save invitation should fail for deleted invitation")
}

func (s *invitationBlackBoxTest) TestCreateResourceInvitation() {
	invitation, err := s.CreateTestResourceInvitation()
	require.NoError(s.T(), err)

	invitations, err := s.repo.ListForResource(s.Ctx, *invitation.ResourceID)
	require.NoError(s.T(), err)
	require.Equal(s.T(), 1, len(invitations))

	require.Equal(s.T(), invitation.ResourceID, invitations[0].ResourceID)
	require.Equal(s.T(), invitation.IdentityID, invitations[0].IdentityID)
	require.False(s.T(), invitations[0].Member)
}

func (s *invitationBlackBoxTest) TestAddAndListRoles() {
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

func (s *invitationBlackBoxTest) TestAddRoleFailsForInvalidRoleID() {
	invitation, err := s.CreateTestInvitation()
	require.NoError(s.T(), err)

	err = s.repo.AddRole(s.Ctx, invitation.InvitationID, uuid.NewV4())
	require.Error(s.T(), err, "add role should return error for nonexistent role")

	roles, err := s.repo.ListRoles(s.Ctx, invitation.InvitationID)
	require.NoError(s.T(), err)

	require.Equal(s.T(), 0, len(roles))
}

func (s *invitationBlackBoxTest) CreateTestInvitation() (invitationRepo.Invitation, error) {
	var invitation invitationRepo.Invitation

	orgIdentity, err := testsupport.CreateTestOrganizationIdentity(s.DB)
	if err != nil {
		return invitation, err
	}

	userIdentity, err := testsupport.CreateTestUser(s.DB, &testsupport.TestUser)
	if err != nil {
		return invitation, err
	}

	invitation = invitationRepo.Invitation{
		InviteTo:   &orgIdentity.ID,
		IdentityID: userIdentity.ID,
		Member:     false,
	}

	err = s.repo.Create(s.Ctx, &invitation)
	return invitation, err
}

func (s *invitationBlackBoxTest) CreateTestResourceInvitation() (invitationRepo.Invitation, error) {
	var invitation invitationRepo.Invitation

	resourceType, err := s.Application.ResourceTypeRepository().Lookup(s.Ctx, authorization.IdentityResourceTypeOrganization)
	require.NoError(s.T(), err)

	resource, err := testsupport.CreateTestResource(s.Ctx, s.DB, *resourceType, "foo", nil)
	require.NoError(s.T(), err)

	userIdentity, err := testsupport.CreateTestUser(s.DB, &testsupport.TestUser)
	if err != nil {
		return invitation, err
	}

	invitation = invitationRepo.Invitation{
		ResourceID: &resource.ResourceID,
		IdentityID: userIdentity.ID,
		Member:     false,
	}

	err = s.repo.Create(s.Ctx, &invitation)
	return invitation, err
}
