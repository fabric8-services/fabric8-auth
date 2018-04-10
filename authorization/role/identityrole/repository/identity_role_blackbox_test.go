package repository_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	scope "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/scope/repository"
	identityrole "github.com/fabric8-services/fabric8-auth/authorization/role/identityrole/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type identityRoleBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo                  identityrole.IdentityRoleRepository
	identityRepo          account.IdentityRepository
	resourceRepo          resource.ResourceRepository
	resourceTypeRepo      resourcetype.ResourceTypeRepository
	resourceTypeScopeRepo scope.ResourceTypeScopeRepository
	roleRepo              role.RoleRepository
}

func TestRunIdentityRoleBlackBoxTest(t *testing.T) {
	suite.Run(t, &identityRoleBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *identityRoleBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.DB.LogMode(true)
	s.repo = identityrole.NewIdentityRoleRepository(s.DB)
	s.identityRepo = account.NewIdentityRepository(s.DB)
	s.resourceTypeRepo = resourcetype.NewResourceTypeRepository(s.DB)
	s.resourceTypeScopeRepo = scope.NewResourceTypeScopeRepository(s.DB)
	s.roleRepo = role.NewRoleRepository(s.DB)
	s.resourceRepo = resource.NewResourceRepository(s.DB)
}

func (s *identityRoleBlackBoxTest) TestOKToDelete() {
	// create 2 identity roles, where the first one would be deleted.
	identityRole := createAndLoadIdentityRole(s)
	createAndLoadIdentityRole(s)

	err := s.repo.Delete(s.Ctx, identityRole.IdentityRoleID)
	assert.Nil(s.T(), err)

	// lets see how many are present.
	identityRoles, err := s.repo.List(s.Ctx)
	require.Nil(s.T(), err, "Could not list identity roles")
	require.True(s.T(), len(identityRoles) > 0)

	for _, data := range identityRoles {
		// The role 'role' was deleted and rest were not deleted, hence we check
		// that none of the role objects returned include the one deleted.
		require.NotEqual(s.T(), identityRole.IdentityRoleID.String(), data.IdentityRoleID.String())
	}
}

func (s *identityRoleBlackBoxTest) TestOKToLoad() {
	createAndLoadIdentityRole(s)
}

func (s *identityRoleBlackBoxTest) TestExistsRole() {
	t := s.T()

	t.Run("identity role exists", func(t *testing.T) {
		//t.Parallel()
		identityRole := createAndLoadIdentityRole(s)
		// when
		err := s.repo.CheckExists(s.Ctx, identityRole.IdentityRoleID.String())
		// then
		require.Nil(t, err)
	})

	t.Run("identity role doesn't exist", func(t *testing.T) {
		//t.Parallel()
		// Check not existing
		err := s.repo.CheckExists(s.Ctx, uuid.NewV4().String())
		// then
		require.IsType(t, errors.NotFoundError{}, err)
	})

}

func (s *identityRoleBlackBoxTest) TestListByResourceAndIdentity() {
	t := s.T()
	createdIdentityRole := createAndLoadIdentityRole(s)

	returnedRoles, err := s.repo.ListByIdentityAndResource(s.Ctx, createdIdentityRole.ResourceID, createdIdentityRole.IdentityID)
	require.NoError(t, err)
	require.Len(t, returnedRoles, 1)
	validateIdentityRole(s, *createdIdentityRole, returnedRoles[0])

	createdResource, err := s.resourceRepo.Load(s.Ctx, createdIdentityRole.ResourceID)
	//createdRole, err := s.roleRepo.Load(s.Ctx, createdIdentityRole.RoleID)
	createdIdentity, err := s.identityRepo.Load(s.Ctx, createdIdentityRole.IdentityID)
	createdResourceType, err := s.resourceTypeRepo.Load(s.Ctx, createdResource.ResourceTypeID)

	for i := 0; i < 10; i++ {
		newRole := role.Role{
			ResourceType:   *createdResourceType,
			ResourceTypeID: createdResourceType.ResourceTypeID,
			Name:           uuid.NewV4().String(),
			RoleID:         uuid.NewV4(),
		}
		err := s.roleRepo.Create(s.Ctx, &newRole)
		require.NoError(s.T(), err)

		newIdentityRole := identityrole.IdentityRole{
			IdentityRoleID: uuid.NewV4(),
			Role:           newRole,
			RoleID:         newRole.RoleID,
			//Resource:       *createdResource,
			ResourceID: createdIdentityRole.ResourceID,
			Identity:   *createdIdentity,
			IdentityID: createdIdentity.ID,
		}
		s.repo.Create(s.Ctx, &newIdentityRole)
	}

	returnedRoles, err = s.repo.ListByIdentityAndResource(s.Ctx, createdIdentityRole.ResourceID, createdIdentityRole.IdentityID)
	require.Len(t, returnedRoles, 11)

}

func (s *identityRoleBlackBoxTest) TestOKToSave() {
	//identityRole := createAndLoadIdentityRole(s)

	//identityRole.Name = "newRoleNameTestType"
	//err := s.repo.Save(s.ctx, identityRole)
	//require.Nil(s.T(), err, "Could not update identity role")

	//updatedIdentityRole, err := s.repo.Load(s.ctx, identityRole.IdentityRoleID)
	//require.Nil(s.T(), err, "Could not load identity role")
	//assert.Equal(s.T(), identityRole.Name, updatedIdentityRole.Name)
}

func createAndLoadIdentityRole(s *identityRoleBlackBoxTest) *identityrole.IdentityRole {
	ir, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(s.T(), err)
	return ir
}

func validateIdentityRole(s *identityRoleBlackBoxTest, expected identityrole.IdentityRole, actual identityrole.IdentityRole) {
	require.Equal(s.T(), expected.IdentityID, actual.IdentityID)
	require.Equal(s.T(), expected.ResourceID, actual.ResourceID)
	require.Equal(s.T(), expected.RoleID, actual.RoleID)
}
