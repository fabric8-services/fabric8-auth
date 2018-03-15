package repository_test

import (
	"testing"

	resourcetyperepo "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type roleMappingBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo rolerepo.RoleMappingRepository
}

func TestRunRoleMappingBlackBoxTest(t *testing.T) {
	suite.Run(t, &roleMappingBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *roleMappingBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.DB.LogMode(true)
	s.repo = rolerepo.NewRoleMappingRepository(s.DB)
}

func (s *roleMappingBlackBoxTest) TestOKToDelete() {

	rm1, err := s.createTestRoleMapping(authorization.IdentityResourceTypeOrganization, "employee", authorization.IdentityResourceTypeTeam, "member")
	require.NoError(s.T(), err)

	_, err = s.createTestRoleMapping(authorization.IdentityResourceTypeOrganization, "manager", authorization.IdentityResourceTypeGroup, "admin")
	require.NoError(s.T(), err)

	mappings, err := s.repo.List(s.Ctx)
	require.Nil(s.T(), err, "Could not list role mappings")

	require.Equal(s.T(), 2, len(mappings))

	err = s.repo.Delete(s.Ctx, rm1.RoleMappingID)
	assert.Nil(s.T(), err)

	// there should be one mapping now
	mappings, err = s.repo.List(s.Ctx)
	require.Nil(s.T(), err, "Could not list role mappings")
	require.Equal(s.T(), 1, len(mappings))

	for _, data := range mappings {
		// The role mapping rm1 was deleted while rm2 was not deleted, hence we check
		// that none of the role mappings returned include the deleted record.
		require.NotEqual(s.T(), rm1.RoleMappingID.String(), data.RoleMappingID.String())
	}
}

func (s *roleMappingBlackBoxTest) createTestRoleMapping(fromResourceTypeName string, fromRoleName string, toResourceTypeName string, toRoleName string) (rolerepo.RoleMapping, error) {
	resourceTypeRepo := resourcetyperepo.NewResourceTypeRepository(s.DB)

	var rm rolerepo.RoleMapping

	fromResourceType, err := resourceTypeRepo.Lookup(s.Ctx, fromResourceTypeName)
	if err != nil {
		return rm, err
	}

	toResourceType, err := resourceTypeRepo.Lookup(s.Ctx, toResourceTypeName)
	if err != nil {
		return rm, err
	}

	fromRole, err := testsupport.CreateTestRole(s.Ctx, s.DB, *fromResourceType, fromRoleName)
	if err != nil {
		return rm, err
	}

	toRole, err := testsupport.CreateTestRole(s.Ctx, s.DB, *toResourceType, toRoleName)
	if err != nil {
		return rm, err
	}

	resource, err := testsupport.CreateTestResource(s.Ctx, s.DB, *fromResourceType, "Test-Role-Mapped-Resource", nil)
	if err != nil {
		return rm, err
	}

	rm = rolerepo.RoleMapping{
		ResourceID: resource.ResourceID,
		FromRoleID: fromRole.RoleID,
		ToRoleID:   toRole.RoleID,
	}

	err = s.repo.Create(s.Ctx, &rm)
	return rm, err
}

func (s *roleMappingBlackBoxTest) TestOKToLoad() {

}

func (s *roleMappingBlackBoxTest) TestExistsRoleMapping() {

}

func (s *roleMappingBlackBoxTest) TestOKToSave() {

}
