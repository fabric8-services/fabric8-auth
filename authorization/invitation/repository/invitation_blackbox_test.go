package repository_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization"
	invitationRepo "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	roleRepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

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

func (s *invitationBlackBoxTest) TestDeleteFailsForInvalidInvitation() {
	err := s.repo.Delete(s.Ctx, uuid.NewV4())
	require.Error(s.T(), err)
	require.IsType(s.T(), errors.NotFoundError{}, err)
}

func (s *invitationBlackBoxTest) TestDeleteUnknownFails() {
	id := uuid.NewV4()

	err := s.repo.Delete(s.Ctx, id)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "invitation with id '%s' not found", id.String())
}

func (s *invitationBlackBoxTest) TestDeleteInvitationRolesOK() {
	space := s.Graph.CreateSpace()
	resourceType := s.Graph.LoadResourceType(authorization.ResourceTypeSpace)
	role := s.Graph.CreateRole(resourceType)
	inv := s.Graph.CreateInvitation(space, role)

	invitations, err := s.repo.ListForResource(s.Ctx, *inv.Invitation().ResourceID)
	require.NoError(s.T(), err)
	require.Len(s.T(), invitations, 1)

	roles, err := s.repo.ListRoles(s.Ctx, inv.Invitation().InvitationID)
	require.NoError(s.T(), err)
	require.Len(s.T(), roles, 1)

	err = s.repo.Delete(s.Ctx, inv.Invitation().InvitationID)
	require.NoError(s.T(), err)

	invitations, err = s.repo.ListForResource(s.Ctx, *inv.Invitation().ResourceID)
	require.NoError(s.T(), err)
	require.Equal(s.T(), 0, len(invitations))

	roles, err = s.repo.ListRoles(s.Ctx, inv.Invitation().InvitationID)
	require.NoError(s.T(), err)
	require.Len(s.T(), roles, 0)
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

func (s *invitationBlackBoxTest) TestNotExistsInvitationFails() {
	exists, err := s.repo.CheckExists(s.Ctx, uuid.NewV4())
	require.Error(s.T(), err)
	require.False(s.T(), exists)
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
	role, err := roleRepository.Lookup(s.Ctx, authorization.OrganizationAdminRole, authorization.IdentityResourceTypeOrganization)
	require.NoError(s.T(), err)

	err = s.repo.AddRole(s.Ctx, invitation.InvitationID, role.RoleID)
	require.NoError(s.T(), err)

	roles, err := s.repo.ListRoles(s.Ctx, invitation.InvitationID)
	require.NoError(s.T(), err)

	require.Equal(s.T(), 1, len(roles))
	require.Equal(s.T(), authorization.OrganizationAdminRole, roles[0].Name)
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

func (s *invitationBlackBoxTest) TestFindByAcceptCode() {
	g := s.NewTestGraph()
	i := g.CreateInvitation()

	// Create a couple more invitations for some noise
	g.CreateInvitation()
	g.CreateInvitation()

	invitation, err := s.repo.FindByAcceptCode(s.Ctx, i.Invitation().IdentityID, i.Invitation().AcceptCode)
	require.NoError(s.T(), err)

	require.Equal(s.T(), i.Invitation().InvitationID, invitation.InvitationID)
}

func (s *invitationBlackBoxTest) TestFindByAcceptCodeNotFound() {
	g := s.NewTestGraph()
	i := g.CreateInvitation()

	// Create a couple more invitations for some noise
	g.CreateInvitation()
	g.CreateInvitation()

	_, err := s.repo.FindByAcceptCode(s.Ctx, i.Invitation().IdentityID, uuid.NewV4())
	require.Error(s.T(), err)
	require.IsType(s.T(), errors.NotFoundError{}, err)
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
