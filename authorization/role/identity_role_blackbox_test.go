package role_test

import (
	"context"
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
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

type identityRoleBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo                  role.IdentityRoleRepository
	identityRepo          account.IdentityRepository
	resourceRepo          resource.ResourceRepository
	resourceTypeRepo      resource.ResourceTypeRepository
	resourceTypeScopeRepo resource.ResourceTypeScopeRepository
	roleRepo              role.RoleRepository
	clean                 func()
	ctx                   context.Context
}

func TestRunIdentityRoleBlackBoxTest(t *testing.T) {
	suite.Run(t, &roleBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite("../../config.yaml")})
}

// SetupSuite overrides the DBTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
// It sets up a database connection for all the tests in this suite without polluting global space.
func (s *identityRoleBlackBoxTest) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.ctx = migration.NewMigrationContext(context.Background())
	s.DBTestSuite.PopulateDBTestSuite(s.ctx)
}

func (s *identityRoleBlackBoxTest) SetupTest() {
	s.DB.LogMode(true)
	s.repo = role.NewIdentityRoleRepository(s.DB)
	s.identityRepo = account.NewIdentityRepository(s.DB)
	s.resourceTypeRepo = resource.NewResourceTypeRepository(s.DB)
	s.resourceTypeScopeRepo = resource.NewResourceTypeScopeRepository(s.DB)
	s.roleRepo = role.NewRoleRepository(s.DB)
	s.clean = cleaner.DeleteCreatedEntities(s.DB)
}

func (s *identityRoleBlackBoxTest) TearDownTest() {
	s.clean()
}

func (s *identityRoleBlackBoxTest) TestOKToDelete() {
	// create 2 identity roles, where the first one would be deleted.
	identityRole := createAndLoadIdentityRole(s)
	createAndLoadIdentityRole(s)

	err := s.repo.Delete(s.ctx, identityRole.IdentityRoleID)
	assert.Nil(s.T(), err)

	// lets see how many are present.
	identityRoles, err := s.repo.List(s.ctx)
	require.Nil(s.T(), err, "Could not list identity roles")
	require.True(s.T(), len(identityRoles) > 0)

	for _, data := range identityRoles {
		// The role 'role' was deleted and rest were not deleted, hence we check
		// that none of the role objects returned include the one deleted.
		require.NotEqual(s.T(), identityRole.IdentityRoleID.String(), data.IdentityRoleID.String())
	}
}

func (s *identityRoleBlackBoxTest) TestOKToLoad() {
	t := s.T()
	res.Require(t, res.Database)

	createAndLoadIdentityRole(s)
}

func (s *identityRoleBlackBoxTest) TestExistsRole() {
	t := s.T()
	res.Require(t, res.Database)

	t.Run("identity role exists", func(t *testing.T) {
		//t.Parallel()
		identityRole := createAndLoadIdentityRole(s)
		// when
		err := s.repo.CheckExists(s.ctx, identityRole.IdentityRoleID.String())
		// then
		require.Nil(t, err)
	})

	t.Run("identity role doesn't exist", func(t *testing.T) {
		//t.Parallel()
		// Check not existing
		err := s.repo.CheckExists(s.ctx, uuid.NewV4().String())
		// then
		require.IsType(s.T(), errors.NotFoundError{}, err)
	})
}

func (s *identityRoleBlackBoxTest) TestOKToSave() {
	t := s.T()
	res.Require(t, res.Database)

	//identityRole := createAndLoadIdentityRole(s)

	//identityRole.Name = "newRoleNameTestType"
	//err := s.repo.Save(s.ctx, identityRole)
	//require.Nil(s.T(), err, "Could not update identity role")

	//updatedIdentityRole, err := s.repo.Load(s.ctx, identityRole.IdentityRoleID)
	//require.Nil(s.T(), err, "Could not load identity role")
	//assert.Equal(s.T(), identityRole.Name, updatedIdentityRole.Name)
}

func createAndLoadIdentityRole(s *identityRoleBlackBoxTest) *role.IdentityRole {
	identity := &account.Identity{
		ID:           uuid.NewV4(),
		Username:     "identity_role_blackbox_test_someuserTestIdentity2",
		ProviderType: account.KeycloakIDP}

	err := s.identityRepo.Create(s.ctx, identity)
	require.Nil(s.T(), err, "Could not create identity")

	resourceType := &resource.ResourceType{
		ResourceTypeID: uuid.NewV4(),
		Name:           "identity_role_blackbox_test_Area" + uuid.NewV4().String(),
		Description:    "An area is a logical grouping within a space",
	}

	err = s.resourceTypeRepo.Create(s.ctx, resourceType)
	require.Nil(s.T(), err, "Could not create resource type")

	resourceTypeScope := &resource.ResourceTypeScope{
		ResourceTypeScopeID: uuid.NewV4(),
		ResourceType:        *resourceType,
		ResourceTypeID:      resourceType.ResourceTypeID,
		Name:                "identity_role_blackbox_test_collaborate" + uuid.NewV4().String(),
		Description:         "Collaborators may perform many operations within an area",
	}

	err = s.resourceTypeScopeRepo.Create(s.ctx, resourceTypeScope)
	require.Nil(s.T(), err, "Could not create resource type scope")

	res := &resource.Resource{
		ResourceID:     uuid.NewV4().String(),
		ParentResource: nil,
		Owner:          *identity,
		ResourceType:   *resourceType,
		Description:    "identity_role_blackbox_test_A description of the created resource",
	}

	err = s.resourceRepo.Create(s.ctx, res)
	require.Nil(s.T(), err, "Could not create resource")

	r := &role.Role{
		RoleID:         uuid.NewV4(),
		ResourceType:   *resourceType,
		ResourceTypeID: resourceType.ResourceTypeID,
		Name:           "identity_role_blackbox_test_admin" + uuid.NewV4().String(),
		//Scopes:         []resource.ResourceTypeScope{*resourceTypeScope},
	}

	err = s.roleRepo.Create(s.ctx, r)
	require.Nil(s.T(), err, "Could not create role")

	identityRole := &role.IdentityRole{
		IdentityRoleID: uuid.NewV4(),
		Identity:       *identity,
		Resource:       *res,
		Role:           *r,
	}

	createdIdentityRole, err := s.repo.Load(s.ctx, identityRole.IdentityRoleID)
	require.Nil(s.T(), err, "Could not load identity role")
	require.Equal(s.T(), identityRole.Identity.Username, createdIdentityRole.Identity.Username)
	require.Equal(s.T(), identityRole.Resource.ResourceID, createdIdentityRole.Resource.ResourceID)

	return createdIdentityRole
}
