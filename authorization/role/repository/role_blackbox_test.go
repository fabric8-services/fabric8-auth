package repository_test

import (
	"testing"

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
	{ResourceTypeName: "identity/organization", RoleName: "owner"},
}

func TestRunRoleBlackBoxTest(t *testing.T) {
	suite.Run(t, &roleBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *roleBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.DB.LogMode(true)
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
		_, err = s.repo.CheckExists(s.Ctx, role.RoleID.String())
		// then
		require.Nil(t, err)
	})

	t.Run("role doesn't exist", func(t *testing.T) {
		//t.Parallel()
		// Check not existing
		_, err := s.repo.CheckExists(s.Ctx, uuid.NewV4().String())
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
