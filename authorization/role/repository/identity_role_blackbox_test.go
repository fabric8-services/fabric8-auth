package repository_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	scope "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/scope/repository"
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
	repo                  role.IdentityRoleRepository
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
	s.repo = role.NewIdentityRoleRepository(s.DB)
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

	// let's create as many randome identityroles

	someOtherResource, err := testsupport.CreateTestResourceWithDefaultType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), someOtherResource)

	someOtherIdentity, err := testsupport.CreateTestIdentityAndUser(s.DB, uuid.NewV4().String(), "KC")
	require.NoError(s.T(), err)
	require.NotNil(s.T(), someOtherIdentity)

	var createdIdentityRoles []role.IdentityRole

	// insert the one previously created
	createdIdentityRoles = append(createdIdentityRoles, *createdIdentityRole)

	for i := 0; i < 10; i++ {
		newRole := role.Role{
			ResourceType:   *createdResourceType,
			ResourceTypeID: createdResourceType.ResourceTypeID,
			Name:           uuid.NewV4().String(),
			RoleID:         uuid.NewV4(),
		}
		err := s.roleRepo.Create(s.Ctx, &newRole)
		require.NoError(s.T(), err)

		newIdentityRole := &role.IdentityRole{
			IdentityRoleID: uuid.NewV4(),
			Role:           newRole,
			RoleID:         newRole.RoleID,
			ResourceID:     createdResource.ResourceID,
			IdentityID:     createdIdentity.ID,
		}

		s.repo.Create(s.Ctx, newIdentityRole)
		createdIdentityRoles = append(createdIdentityRoles, *newIdentityRole)

		// create dirty data
		identityRoleWithDifferentResource := role.IdentityRole{
			IdentityRoleID: uuid.NewV4(),
			Role:           newRole,
			RoleID:         newRole.RoleID,
			ResourceID:     someOtherResource.ResourceID,
			Identity:       *createdIdentity,
			IdentityID:     createdIdentity.ID,
		}
		s.repo.Create(s.Ctx, &identityRoleWithDifferentResource)

		identityRoleWithDifferentIdentity := role.IdentityRole{
			IdentityRoleID: uuid.NewV4(),
			Role:           newRole,
			RoleID:         newRole.RoleID,
			ResourceID:     createdIdentityRole.ResourceID,
			Identity:       someOtherIdentity,
			IdentityID:     someOtherIdentity.ID,
		}
		s.repo.Create(s.Ctx, &identityRoleWithDifferentIdentity)

	}

	returnedRoles, err = s.repo.ListByIdentityAndResource(s.Ctx, createdIdentityRole.ResourceID, createdIdentityRole.IdentityID)
	require.Len(t, returnedRoles, 11)

	for _, actualRole := range returnedRoles {
		checkExists(s, createdIdentityRoles, actualRole)
	}

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

func createAndLoadIdentityRole(s *identityRoleBlackBoxTest) *role.IdentityRole {
	ir, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(s.T(), err)
	return ir
}

func validateIdentityRole(s *identityRoleBlackBoxTest, expected role.IdentityRole, actual role.IdentityRole) {
	require.Equal(s.T(), expected.IdentityRoleID, actual.IdentityRoleID)
	require.Equal(s.T(), expected.IdentityID, actual.IdentityID)
	require.Equal(s.T(), expected.ResourceID, actual.ResourceID)
	require.Equal(s.T(), expected.RoleID, actual.RoleID)
}

func checkExists(s *identityRoleBlackBoxTest, expected []role.IdentityRole, actual role.IdentityRole) {
	found := false
	for _, expectedRole := range expected {
		if expectedRole.IdentityRoleID.String() == actual.IdentityRoleID.String() {
			found = true
			validateIdentityRole(s, expectedRole, actual)
			break
		}
	}
	require.True(s.T(), found)
}
