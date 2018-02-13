package authorization_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/authorization/model"
	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/test"
	"github.com/satori/go.uuid"

	"github.com/fabric8-services/fabric8-auth/authorization/common"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type organizationServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo             resource.ResourceRepository
	identityRepo     account.IdentityRepository
	identityRoleRepo role.IdentityRoleRepository
	resourceRepo     resource.ResourceRepository
	resourceTypeRepo resource.ResourceTypeRepository
	roleRepo         role.RoleRepository
	orgService       authorization.OrganizationService
}

func TestRunOrganizationServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &organizationServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *organizationServiceBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = resource.NewResourceRepository(s.DB)
	s.identityRepo = account.NewIdentityRepository(s.DB)
	s.identityRoleRepo = role.NewIdentityRoleRepository(s.DB)
	s.resourceRepo = resource.NewResourceRepository(s.DB)
	s.resourceTypeRepo = resource.NewResourceTypeRepository(s.DB)
	s.roleRepo = role.NewRoleRepository(s.DB)

	s.orgService = model.NewOrganizationModelService(s.DB, &test.TestRepositories{
		FIdentityRepository:     s.identityRepo,
		FIdentityRoleRepository: s.identityRoleRepo,
		FResourceRepository:     s.resourceRepo,
		FResourceTypeRepository: s.resourceTypeRepo,
		FRoleRepository:         s.roleRepo,
	})
}

func (s *organizationServiceBlackBoxTest) TestCreateOrganization() {
	identity := &account.Identity{
		ID:           uuid.NewV4(),
		Username:     "identity_role_blackbox_test_someuserTestIdentity2",
		ProviderType: account.KeycloakIDP}

	err := s.identityRepo.Create(s.Ctx, identity)
	require.Nil(s.T(), err, "Could not create identity")

	orgId, err := s.orgService.CreateOrganization(s.Ctx, identity.ID, "Test Organization ZXYAAA")
	require.Nil(s.T(), err, "Could not create organization")

	// Load the organization's identity
	orgIdentity, err := s.identityRepo.Load(s.Ctx, *orgId)
	require.Nil(s.T(), err, "Could not load organization's identity")

	// Assert that the identity resource ID is set
	require.NotNil(s.T(), orgIdentity.IdentityResourceID, "Organization identity's resource id is nil")
	require.NotEmpty(s.T(), orgIdentity.IdentityResourceID, "Organization identity's resource id is not set")

	// Load the organization's resource
	orgResource, err := s.resourceRepo.Load(s.Ctx, *orgIdentity.IdentityResourceID)
	require.Nil(s.T(), err, "Could not load the organization's resource")

	require.Equal(s.T(), common.IdentityResourceTypeOrganization, orgResource.ResourceType.Name, "Organization resource type is invalid")
}

func (s *organizationServiceBlackBoxTest) TestListOrganization() {
	identity := &account.Identity{
		ID:           uuid.NewV4(),
		Username:     "identity_role_blackbox_test_someuserTestIdentity2",
		ProviderType: account.KeycloakIDP}

	err := s.identityRepo.Create(s.Ctx, identity)
	require.Nil(s.T(), err, "Could not create identity")

	orgId, err := s.orgService.CreateOrganization(s.Ctx, identity.ID, "Test Organization MMMYYY")
	require.Nil(s.T(), err, "Could not create organization")

	orgs, err := s.orgService.ListOrganizations(s.Ctx, identity.ID)
	require.Nil(s.T(), err, "Could not list organizations")

	// Check we get one organization back
	require.Equal(s.T(), 1, len(orgs), "Did not get exactly 1 organization in list")

	org := orgs[0]

	require.Equal(s.T(), *orgId, org.OrganizationID, "Organization ID is different")
	require.Equal(s.T(), false, org.Member, "User should not be a member of newly created organization")
	require.Equal(s.T(), "Test Organization MMMYYY", org.Name, "Organization name is different")
	require.Equal(s.T(), 1, len(org.Roles), "New organization should have assigned exactly 1 role")
	require.Equal(s.T(), common.OrganizationOwnerRole, org.Roles[0], "New organization should have assigned owner role")
}
