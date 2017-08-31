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

	"github.com/satori/go.uuid"

	res "github.com/fabric8-services/fabric8-auth/resource"
)

type roleBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo                  role.RoleRepository
	resourceTypeRepo      resource.ResourceTypeRepository
	resourceTypeScopeRepo resource.ResourceTypeScopeRepository
	clean                 func()
	ctx                   context.Context
}

func TestRunRoleBlackBoxTest(t *testing.T) {
	suite.Run(t, &roleBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite("../../config.yaml")})
}

// SetupSuite overrides the DBTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
// It sets up a database connection for all the tests in this suite without polluting global space.
func (s *roleBlackBoxTest) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.ctx = migration.NewMigrationContext(context.Background())
	s.DBTestSuite.PopulateDBTestSuite(s.ctx)
}

func (s *roleBlackBoxTest) SetupTest() {
	s.DB.LogMode(true)
	s.repo = role.NewRoleRepository(s.DB)
	s.resourceTypeRepo = resource.NewResourceTypeRepository(s.DB)
	s.resourceTypeScopeRepo = resource.NewResourceTypeScopeRepository(s.DB)
	s.clean = cleaner.DeleteCreatedEntities(s.DB)
}

func (s *roleBlackBoxTest) TearDownTest() {
	s.clean()
}

func (s *roleBlackBoxTest) TestOKToDelete() {
	t := s.T()
	res.Require(t, res.Database)

	// create 2 roles, where the first one would be deleted.
	role := createAndLoadRole(s)
	createAndLoadRole(s)

	err := s.repo.Delete(s.ctx, role.RoleID)
	assert.Nil(s.T(), err)

	// lets see how many are present.
	roles, err := s.repo.List(s.ctx)
	require.Nil(s.T(), err, "Could not list roles")
	require.True(s.T(), len(roles) > 0)

	for _, data := range roles {
		// The role 'role' was deleted and rest were not deleted, hence we check
		// that none of the role objects returned include the one deleted.
		require.NotEqual(s.T(), role.RoleID.String(), data.RoleID.String())
	}
}

func (s *roleBlackBoxTest) TestOKToLoad() {
	t := s.T()
	res.Require(t, res.Database)

	createAndLoadRole(s)
}

func (s *roleBlackBoxTest) TestExistsRole() {
	t := s.T()
	res.Require(t, res.Database)

	t.Run("role exists", func(t *testing.T) {
		//t.Parallel()
		role := createAndLoadRole(s)
		// when
		_, err := s.repo.CheckExists(s.ctx, role.RoleID.String())
		// then
		require.Nil(t, err)
	})

	t.Run("role doesn't exist", func(t *testing.T) {
		//t.Parallel()
		// Check not existing
		_, err := s.repo.CheckExists(s.ctx, uuid.NewV4().String())
		// then
		require.IsType(s.T(), errors.NotFoundError{}, err)
	})
}

func (s *roleBlackBoxTest) TestOKToSave() {
	t := s.T()
	res.Require(t, res.Database)

	role := createAndLoadRole(s)

	role.Name = "newRoleNameTestType"
	err := s.repo.Save(s.ctx, role)
	require.Nil(s.T(), err, "Could not update role")

	updatedRole, err := s.repo.Load(s.ctx, role.RoleID)
	require.Nil(s.T(), err, "Could not load role")
	assert.Equal(s.T(), role.Name, updatedRole.Name)
}

func (s *roleBlackBoxTest) TestScopes() {
	t := s.T()
	res.Require(t, res.Database)

	role := createAndLoadRole(s);

	resourceTypeScopes, err := s.resourceTypeScopeRepo.List(s.ctx, &role.ResourceType)
	require.Nil(s.T(), err, "Could not load resource type scopes")
	require.NotZero(s.T(), len(resourceTypeScopes))

	err = s.repo.AddScope(s.ctx, role, &resourceTypeScopes[0])
	require.Nil(s.T(), err, "Role scope not created")

	roleScopes, err := s.repo.ListScopes(s.ctx, role)
	require.NotNil(s.T(), roleScopes, "Could not load role scopes")

	require.Equal(s.T(), len(roleScopes), 1, "Should be exactly one role scope")
}

func createAndLoadRole(s *roleBlackBoxTest) *role.Role {

	resourceType := &resource.ResourceType{
		ResourceTypeID: uuid.NewV4(),
		Name:           "Area" + uuid.NewV4().String(),
		Description:    "An area is a logical grouping within a space",
	}

	err := s.resourceTypeRepo.Create(s.ctx, resourceType)
	require.Nil(s.T(), err, "Could not create resource type")

	resourceTypeScope := &resource.ResourceTypeScope{
		ResourceTypeScopeID: uuid.NewV4(),
		ResourceType:        *resourceType,
		ResourceTypeID:      resourceType.ResourceTypeID,
		Name:                "collaborate" + uuid.NewV4().String(),
		Description:         "Collaborators may perform many operations within an area",
	}

	err = s.resourceTypeScopeRepo.Create(s.ctx, resourceTypeScope)
	require.Nil(s.T(), err, "Could not create resource type scope")

	role := &role.Role{
		RoleID:         uuid.NewV4(),
		ResourceType:   *resourceType,
		ResourceTypeID: resourceType.ResourceTypeID,
		Name:           "admin" + uuid.NewV4().String(),
		//Scopes:         []resource.ResourceTypeScope{*resourceTypeScope},
	}

	err = s.repo.Create(s.ctx, role)
	require.Nil(s.T(), err, "Could not create role")

	createdRole, err := s.repo.Load(s.ctx, role.RoleID)
	require.Nil(s.T(), err, "Could not load role")
	require.Equal(s.T(), role.Name, createdRole.Name)
	require.Equal(s.T(), role.ResourceTypeID, createdRole.ResourceTypeID)

	return createdRole
}
