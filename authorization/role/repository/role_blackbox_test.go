package repository_test

import (
	"context"
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type roleBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo role.RoleRepository
}

type KnownRole struct {
	ResourceTypeName string
	RoleName         string
}

var knownRoles = []KnownRole{
	{ResourceTypeName: "identity/organization", RoleName: "admin"},
}

func TestRunRoleBlackBoxTest(t *testing.T) {
	suite.Run(t, &roleBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *roleBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = role.NewRoleRepository(s.DB)
}

func (s *roleBlackBoxTest) TestOKToDelete() {
	// create 2 roles, where the first one would be deleted.
	role, err := testsupport.CreateTestRoleWithDefaultType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), role)

	_, err = testsupport.CreateTestRoleWithDefaultType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)

	err = s.repo.Delete(s.Ctx, role.RoleID)
	assert.Nil(s.T(), err)

	// lets see how many are present.
	roles, err := s.repo.List(s.Ctx)
	require.Nil(s.T(), err, "Could not list roles")
	require.True(s.T(), len(roles) > 0)

	for _, data := range roles {
		// The role 'role' was deleted and rest were not deleted, hence we check
		// that none of the role objects returned include the one deleted.
		require.NotEqual(s.T(), role.RoleID.String(), data.RoleID.String())
	}
}

func (s *roleBlackBoxTest) TestDeleteUnknownFails() {
	id := uuid.NewV4()

	err := s.repo.Delete(s.Ctx, id)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "role with id '%s' not found", id.String())
}

func (s *roleBlackBoxTest) TestOKToLoad() {
	r, err := testsupport.CreateTestRoleWithDefaultType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), r)

	_, err = s.repo.Load(s.Ctx, r.RoleID)
	require.NoError(s.T(), err)
}

func (s *roleBlackBoxTest) TestExistsRole() {
	t := s.T()

	t.Run("role exists", func(t *testing.T) {
		//t.Parallel()
		role, err := testsupport.CreateTestRoleWithDefaultType(s.Ctx, s.DB, uuid.NewV4().String())
		require.NoError(s.T(), err)
		require.NotNil(s.T(), role)
		// when
		err = s.repo.CheckExists(s.Ctx, role.RoleID.String())
		// then
		require.Nil(t, err)
	})

	t.Run("role doesn't exist", func(t *testing.T) {
		//t.Parallel()
		// Check not existing
		err := s.repo.CheckExists(s.Ctx, uuid.NewV4().String())
		// then
		require.IsType(s.T(), errors.NotFoundError{}, err)
	})
}

func (s *roleBlackBoxTest) TestOKToSave() {
	role, err := testsupport.CreateTestRoleWithDefaultType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), role)

	role.Name = "newRoleNameTestType"
	err = s.repo.Save(s.Ctx, role)
	require.Nil(s.T(), err, "Could not update role")

	updatedRole, err := s.repo.Load(s.Ctx, role.RoleID)
	require.Nil(s.T(), err, "Could not load role")
	assert.Equal(s.T(), role.Name, updatedRole.Name)
}

func (s *roleBlackBoxTest) TestOKToAddScopes() {
	role, err := testsupport.CreateTestRoleWithDefaultType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), role)

	scope, err := testsupport.CreateTestScope(s.Ctx, s.DB, role.ResourceType, "create")
	require.NoError(s.T(), err)

	err = s.repo.AddScope(s.Ctx, role, scope)
	require.NoError(s.T(), err)

	scopes, err := s.repo.ListScopes(s.Ctx, role)
	require.NoError(s.T(), err)

	require.Equal(s.T(), 1, len(scopes))
	require.Equal(s.T(), scope.ResourceTypeScopeID, scopes[0].ResourceTypeScopeID)
	require.Equal(s.T(), scope.ResourceTypeID, scopes[0].ResourceTypeID)
	require.Equal(s.T(), scope.Name, scopes[0].Name)
}

func (s *roleBlackBoxTest) TestSaveFailsForDeletedRole() {
	role, err := testsupport.CreateTestRoleWithDefaultType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), role)

	err = s.repo.Delete(s.Ctx, role.RoleID)
	require.NoError(s.T(), err)

	role.Name = "newRoleNameTestType"
	err = s.repo.Save(s.Ctx, role)
	require.Error(s.T(), err, "should not be able to save deleted role")
}

func (s *roleBlackBoxTest) TestSaveConflictError() {
	role1, err := testsupport.CreateTestRoleWithDefaultType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), role1)

	role2, err := testsupport.CreateTestRoleWithDefaultType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), role2)

	role2.Name = role1.Name
	err = s.repo.Save(s.Ctx, role2)
	require.Error(s.T(), err)
	require.IsType(s.T(), errors.DataConflictError{}, err)
}

func (s *roleBlackBoxTest) TestCreateConflictError() {
	role1, err := testsupport.CreateTestRoleWithDefaultType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), role1)

	_, err = testsupport.CreateTestRoleWithDefaultType(s.Ctx, s.DB, role1.Name)
	require.Error(s.T(), err)
	require.IsType(s.T(), errors.DataConflictError{}, err)
}

func (s *roleBlackBoxTest) TestKnownRolesExist() {
	t := s.T()

	t.Run("role exists", func(t *testing.T) {

		for _, r := range knownRoles {
			_, err := s.repo.Lookup(s.Ctx, r.RoleName, r.ResourceTypeName)
			// then
			require.Nil(t, err)
		}
	})
}

func (s *roleBlackBoxTest) TestFindRolesByResourceTypeAndIdentity() {

	s.T().Run("individual", func(t *testing.T) {

		t.Run("individual is admin on no space", func(t *testing.T) {
			// given
			g := s.NewTestGraph()
			user := g.CreateUser()
			space := g.CreateSpace()
			require.Equal(t, authorization.ResourceTypeSpace, space.Resource().ResourceType.Name)
			// when
			roles, err := s.repo.FindRolesByResourceTypeAndIdentity(
				context.Background(),
				authorization.ResourceTypeSpace,
				user.IdentityID())
			// then
			require.NoError(t, err)
			assert.Len(t, roles, 0)
		})

		t.Run("individual is admin on 1 space", func(t *testing.T) {
			// given
			g := s.NewTestGraph()
			user := g.CreateUser()
			space := g.CreateSpace().AddAdmin(user)
			require.Equal(t, authorization.ResourceTypeSpace, space.Resource().ResourceType.Name)
			// when
			roles, err := s.repo.FindRolesByResourceTypeAndIdentity(
				context.Background(),
				authorization.ResourceTypeSpace,
				user.IdentityID())
			// then
			require.NoError(t, err)
			require.Len(t, roles, 1)
			assert.Equal(t, space.Resource().ResourceType.Name, roles[0].ResourceType)
			assert.Equal(t, authorization.SpaceAdminRole, roles[0].RoleName)
			assert.ElementsMatch(t, roles[0].Scopes, []string{
				authorization.ViewSpaceScope,
				authorization.ContributeSpaceScope,
				authorization.ManageSpaceScope,
			})
		})

		t.Run("individual is admin on 2 spaces", func(t *testing.T) {
			// given
			g := s.NewTestGraph()
			user := g.CreateUser()
			space1 := g.CreateSpace().AddAdmin(user)
			require.Equal(t, authorization.ResourceTypeSpace, space1.Resource().ResourceType.Name)
			space2 := g.CreateSpace().AddAdmin(user)
			require.Equal(t, authorization.ResourceTypeSpace, space2.Resource().ResourceType.Name)
			g.CreateSpace() // another space on which the user has no role
			// when
			roles, err := s.repo.FindRolesByResourceTypeAndIdentity(
				context.Background(),
				authorization.ResourceTypeSpace,
				user.IdentityID())
			// then
			require.NoError(t, err)
			require.Len(t, roles, 2)
			// roles should be on space1 and space2, not space3
			for _, r := range roles {
				assert.Contains(t, []string{space1.SpaceID(), space2.SpaceID()}, r.ResourceID)
			}
		})

		t.Run("individual is admin in the parent organization but no default or custom role mapping", func(t *testing.T) {
			// given
			g := s.NewTestGraph()
			user := g.CreateUser()
			org := g.CreateOrganization(user) // user will be creator and admin of the org
			g.CreateSpace(org)
			// here we don't map the admin role in the org to a contributor role in the space,
			// so the user is not considered as a contributor in the created space
			// when
			roles, err := s.repo.FindRolesByResourceTypeAndIdentity(
				context.Background(),
				authorization.ResourceTypeSpace,
				user.IdentityID())
			// then
			require.NoError(t, err)
			assert.Len(t, roles, 0)
		})

		t.Run("individual is contributor in the parent organization with default role mapping", func(t *testing.T) {
			// make sure that the default role mapping is removed after the sub-test above
			defer s.CleanTest()

			// given
			g := s.NewTestGraph()
			user := g.CreateUser()
			org := g.CreateOrganization(user) // user will be creator and admin of the org
			space := g.CreateSpace(org)
			// here we map the admin role in the org to a contributor role in the space,
			// so the user is also considered as a contributor in the created space
			orgAdminRole := g.RoleByNameAndResourceType(authorization.OrganizationAdminRole, org.Resource().ResourceType.Name)
			spaceContributorRole := g.RoleByNameAndResourceType(authorization.SpaceContributorRole, space.Resource().ResourceType.Name)
			spaceType := g.ResourceTypeByID(space.Resource().ResourceType.ResourceTypeID)
			g.CreateDefaultRoleMapping(spaceType, orgAdminRole, spaceContributorRole)
			// when
			roles, err := s.repo.FindRolesByResourceTypeAndIdentity(
				context.Background(),
				authorization.ResourceTypeSpace,
				user.IdentityID())
			// then
			require.NoError(t, err)
			require.Len(t, roles, 1)
			assert.Equal(t, space.Resource().ResourceType.Name, roles[0].ResourceType)
			assert.Equal(t, authorization.SpaceContributorRole, roles[0].RoleName)
			assert.ElementsMatch(t, roles[0].Scopes, []string{
				authorization.ContributeSpaceScope,
				authorization.ViewSpaceScope,
			})
		})

		t.Run("individual is admin in the parent organization with custom role mapping", func(t *testing.T) {
			t.Skipf("not implemented yet")
		})

	})

	s.T().Run("teams", func(t *testing.T) {

		t.Run("individual belongs to admin team on no space", func(t *testing.T) {
			// given
			g := s.NewTestGraph()
			user := g.CreateUser()
			g.CreateTeam("team").AddMember(user)
			space := g.CreateSpace()
			require.Equal(t, authorization.ResourceTypeSpace, space.Resource().ResourceType.Name)
			// when
			roles, err := s.repo.FindRolesByResourceTypeAndIdentity(
				context.Background(),
				authorization.ResourceTypeSpace,
				user.IdentityID())
			// then
			require.NoError(t, err)
			assert.Len(t, roles, 0)
		})

		t.Run("individual belongs to admin team on 1 space", func(t *testing.T) {
			// given
			g := s.NewTestGraph()
			user := g.CreateUser()
			team := g.CreateTeam("team").AddMember(user)
			space := g.CreateSpace().AddAdmin(team)
			require.Equal(t, authorization.ResourceTypeSpace, space.Resource().ResourceType.Name)
			// when
			roles, err := s.repo.FindRolesByResourceTypeAndIdentity(
				context.Background(),
				authorization.ResourceTypeSpace,
				user.IdentityID())
			// then
			require.NoError(t, err)
			require.Len(t, roles, 1)
			assert.Equal(t, space.Resource().ResourceType.Name, roles[0].ResourceType)
			assert.Equal(t, authorization.SpaceAdminRole, roles[0].RoleName)
			assert.ElementsMatch(t, roles[0].Scopes, []string{
				authorization.ViewSpaceScope,
				authorization.ContributeSpaceScope,
				authorization.ManageSpaceScope,
			})
		})

		t.Run("individual is member of admin team in the parent organization with default role mapping", func(t *testing.T) {
			// make sure that the default role mapping is removed after the sub-test above
			defer s.CleanTest()
			// given
			g := s.NewTestGraph()
			creator := g.CreateUser()
			org := g.CreateOrganization(creator) // team (hence user) will be creator and admin of the org
			user := g.CreateUser()
			team := g.CreateTeam("team").AddMember(user)
			org.AddAdmin(team)
			space := g.CreateSpace(org)
			// here we map the admin role in the org to a contributor role in the space,
			// so the user is also considered as a contributor in the created space
			orgAdminRole := g.RoleByNameAndResourceType(authorization.OrganizationAdminRole, org.Resource().ResourceType.Name)
			spaceContributorRole := g.RoleByNameAndResourceType(authorization.SpaceContributorRole, space.Resource().ResourceType.Name)
			spaceType := g.ResourceTypeByID(space.Resource().ResourceType.ResourceTypeID)
			g.CreateDefaultRoleMapping(spaceType, orgAdminRole, spaceContributorRole)
			// when
			roles, err := s.repo.FindRolesByResourceTypeAndIdentity(
				context.Background(),
				authorization.ResourceTypeSpace,
				user.IdentityID())
			// then
			require.NoError(t, err)
			require.Len(t, roles, 1)
			assert.Equal(t, space.Resource().ResourceType.Name, roles[0].ResourceType)
			assert.Equal(t, authorization.SpaceContributorRole, roles[0].RoleName)
			assert.ElementsMatch(t, roles[0].Scopes, []string{
				authorization.ContributeSpaceScope,
				authorization.ViewSpaceScope,
			})
		})

		t.Run("individual is member of admin team in the parent organization with custom role mapping", func(t *testing.T) {
			t.Skipf("not implemented yet")
		})
	})

}
