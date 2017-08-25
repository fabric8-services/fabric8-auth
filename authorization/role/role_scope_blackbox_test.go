package role_test

import (
	"context"
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport/cleaner"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/migration"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	uuid "github.com/satori/go.uuid"

	res "github.com/fabric8-services/fabric8-auth/resource"
)

type roleScopeBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo  role.RoleScopeRepository
	resourceTypeRepo  resource.ResourceTypeRepository
	resourceTypeScopeRepo resource.ResourceTypeScopeRepository
	roleRepo role.RoleRepository
	clean func()
	ctx   context.Context
}

func TestRunRoleScopeBlackBoxTest(t *testing.T) {
	suite.Run(t, &roleScopeBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite("../../config.yaml")})
}

// SetupSuite overrides the DBTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
// It sets up a database connection for all the tests in this suite without polluting global space.
func (s *roleScopeBlackBoxTest) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.ctx = migration.NewMigrationContext(context.Background())
	s.DBTestSuite.PopulateDBTestSuite(s.ctx)
}

func (s *roleScopeBlackBoxTest) SetupTest() {
	s.DB.LogMode(true)
	s.repo = role.NewRoleScopeRepository(s.DB)
	s.resourceTypeRepo = resource.NewResourceTypeRepository(s.DB)
	s.resourceTypeScopeRepo = resource.NewResourceTypeScopeRepository(s.DB)
	s.roleRepo = role.NewRoleRepository(s.DB)
	s.clean = cleaner.DeleteCreatedEntities(s.DB)
}

func (s *roleScopeBlackBoxTest) TearDownTest() {
	s.clean()
}

func (s *roleScopeBlackBoxTest) TestOKToDelete() {
	t := s.T()
	res.Require(t, res.Database)

	// create 2 roles, where the first one would be deleted.
	roleScope := createAndLoadRoleScope(s)
	createAndLoadRoleScope(s)

	err := s.repo.Delete(s.ctx, roleScope.Scope.ResourceTypeScopeID, roleScope.Role.RoleID)
	assert.Nil(s.T(), err)

	// lets see how many are present.
	roleScopes, err := s.repo.List(s.ctx)
	require.Nil(s.T(), err, "Could not list roles")
	require.True(s.T(), len(roleScopes) > 0)

	for _, data := range roleScopes {
		// The first RoleScope was deleted and rest were not deleted, hence we check
		// that none of the roleScope objects returned include the one deleted.
		require.NotEqual(s.T(), roleScope.Role.RoleID.String(), data.Role.RoleID.String())
		require.NotEqual(s.T(), roleScope.Scope.ResourceTypeScopeID.String(), data.Scope.ResourceTypeScopeID.String())
	}
}

func (s *roleScopeBlackBoxTest) TestOKToLoad() {
	t := s.T()
	res.Require(t, res.Database)

	createAndLoadRoleScope(s)
}

func (s *roleScopeBlackBoxTest) TestExistsRole() {
	t := s.T()
	res.Require(t, res.Database)

	t.Run("role scope exists", func(t *testing.T) {
		//t.Parallel()
		roleScope := createAndLoadRoleScope(s)
		// when
		_, err := s.repo.CheckExists(s.ctx, roleScope.ScopeID.String(), roleScope.RoleID.String())
		// then
		require.Nil(t, err)
	})

	t.Run("role doesn't exist", func(t *testing.T) {
		//t.Parallel()
		// Check not existing
		_, err := s.repo.CheckExists(s.ctx, uuid.NewV4().String(), uuid.NewV4().String())
		// then
		require.IsType(s.T(), errors.NotFoundError{}, err)
	})
}

func (s *roleScopeBlackBoxTest) TestOKToSave() {
	t := s.T()
	res.Require(t, res.Database)

	roleScope := createAndLoadRoleScope(s)

	role := &role.Role{
		RoleID:       uuid.NewV4(),
		ResourceType: roleScope.Role.ResourceType,
		ResourceTypeID: roleScope.Role.ResourceTypeID,
		Name:    "foo",
	}

	err := s.roleRepo.Create(s.ctx, role)
	require.Nil(s.T(), err, "Could not create role")

	err = s.repo.Save(s.ctx, roleScope)
	require.Nil(s.T(), err, "Could not update role scope")

	updatedRoleScope, err := s.repo.Load(s.ctx, roleScope.ScopeID, roleScope.RoleID)
	require.Nil(s.T(), err, "Could not load role scope")

	assert.NotEqual(s.T(), roleScope.Role.Name, updatedRoleScope.Role.Name)
}

func createAndLoadRoleScope(s *roleScopeBlackBoxTest) *role.RoleScope {

	resourceType := &resource.ResourceType{
		ResourceTypeID:       uuid.NewV4(),
		Name:    "Area" + uuid.NewV4().String(),
		Description: "An area is a logical grouping within a space",
	}

	err := s.resourceTypeRepo.Create(s.ctx, resourceType)
	require.Nil(s.T(), err, "Could not create resource type")

	resourceTypeScope := &resource.ResourceTypeScope{
		ResourceTypeScopeID:       uuid.NewV4(),
		ResourceType: *resourceType,
		ResourceTypeID: resourceType.ResourceTypeID,
		Name:    "collaborate" + uuid.NewV4().String(),
		Description: "Collaborators may perform many operations within an area",
	}

	err = s.resourceTypeScopeRepo.Create(s.ctx, resourceTypeScope)
	require.Nil(s.T(), err, "Could not create resource type scope")

	r := &role.Role{
		RoleID:       uuid.NewV4(),
		ResourceType: *resourceType,
		ResourceTypeID: resourceType.ResourceTypeID,
		Name:    "admin" + uuid.NewV4().String(),
	}

	err = s.roleRepo.Create(s.ctx, r)
	require.Nil(s.T(), err, "Could not create role")

	roleScope := &role.RoleScope {
		Scope: *resourceTypeScope,
		ScopeID: resourceTypeScope.ResourceTypeScopeID,
		Role: *r,
		RoleID: r.RoleID,
	}

	err = s.repo.Create(s.ctx, roleScope)
	require.Nil(s.T(), err, "Could not create role scope")

	createdRoleScope, err := s.repo.Load(s.ctx, roleScope.ScopeID, roleScope.RoleID)
	require.Nil(s.T(), err, "Could not load role scope")
	require.Equal(s.T(), roleScope.ScopeID, createdRoleScope.ScopeID)
	require.Equal(s.T(), roleScope.RoleID, createdRoleScope.RoleID)

	return createdRoleScope
}