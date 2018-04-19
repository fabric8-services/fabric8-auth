package controller_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestRolesRest struct {
	gormtestsupport.DBTestSuite
}

func (rest *TestRolesRest) SecuredRolesControllerWithIdentity(identity account.Identity) (*goa.Service, *RolesController) {
	svc := testsupport.ServiceAsUser("Roles-Service", testsupport.TestIdentity)
	return svc, NewRolesController(svc, rest.Application)
}

func TestRunRolesRest(t *testing.T) {
	suite.Run(t, &TestRolesRest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *TestRolesRest) TestListRolesByResourceTypeOK() {

	var createdRoleScopes []role.RoleScope

	newResourceTypeName := uuid.NewV4().String()
	testResourceTypeRef, err := testsupport.CreateTestResourceType(s.Ctx, s.DB, newResourceTypeName)
	require.NoError(s.T(), err)

	// create 10 roles for the above resource type
	for i := 0; i < 10; i++ {
		role, err := testsupport.CreateTestRole(s.Ctx, s.DB, *testResourceTypeRef, uuid.NewV4().String())
		require.NoError(s.T(), err)
		require.NotNil(s.T(), role)

		// associate 10 different scopes for each role.
		for j := 0; j < 10; j++ {

			scope, err := testsupport.CreateTestScope(s.Ctx, s.DB, *testResourceTypeRef, uuid.NewV4().String())
			require.NoError(s.T(), err)
			require.NotNil(s.T(), scope)

			rs, err := testsupport.CreateTestRoleScope(s.Ctx, s.DB, *scope, *role)
			require.NoError(s.T(), err)
			require.NotNil(s.T(), rs)

			createdRoleScopes = append(createdRoleScopes, *rs)
		}
	}

	someOtherResourceType, err := testsupport.CreateTestResourceType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)

	// Add some noise to the data, and ensure non of these are returned.
	for i := 0; i < 3; i++ {
		role, err := testsupport.CreateTestRole(s.Ctx, s.DB, *someOtherResourceType, uuid.NewV4().String())

		require.NoError(s.T(), err)
		require.NotNil(s.T(), role)

		scope, err := testsupport.CreateTestScope(s.Ctx, s.DB, *someOtherResourceType, uuid.NewV4().String())
		require.NoError(s.T(), err)
		require.NotNil(s.T(), scope)

		rs, err := testsupport.CreateTestRoleScope(s.Ctx, s.DB, *scope, *role)
		require.NoError(s.T(), err)
		require.NotNil(s.T(), rs)
	}

	svc, ctrl := s.SecuredRolesControllerWithIdentity(testsupport.TestIdentity)
	_, retrievedRoleScopes := test.ListRolesOK(s.T(), s.Ctx, svc, ctrl, &testResourceTypeRef.Name)

	// check if the count matches the number of legit rolescopes.
	require.Len(s.T(), retrievedRoleScopes.Data, 10)

	// if the above count matches, lets ensure all these returned objects are actually
	// the ones we intended to see.
	s.checkIfCreatedRoleScopesAreReturned(s.DB, *retrievedRoleScopes, createdRoleScopes)
}

func (s *TestRolesRest) TestListRolesByResourceTypeBadRequest() {
	svc, ctrl := s.SecuredRolesControllerWithIdentity(testsupport.TestIdentity)
	test.ListRolesBadRequest(s.T(), s.Ctx, svc, ctrl, nil)
}

func (s *TestRolesRest) TestListRolesByResourceTypeNotFound() {
	svc, ctrl := s.SecuredRolesControllerWithIdentity(testsupport.TestIdentity)
	unknownResourceType := uuid.NewV4().String()
	test.ListRolesNotFound(s.T(), s.Ctx, svc, ctrl, &unknownResourceType)
}

func (s *TestRolesRest) checkIfCreatedRoleScopesAreReturned(db *gorm.DB, roleScopesRetrieved app.Roles, createdRoleScopes []role.RoleScope) {
	foundCreatedRoleScope := false
	for _, rsDB := range createdRoleScopes {
		foundCreatedRoleScope = false
		for _, rsRetrieved := range roleScopesRetrieved.Data {
			require.Equal(s.T(), rsDB.Role.ResourceType.Name, rsRetrieved.ResourceType)
			if rsDB.Role.Name == rsRetrieved.RoleName {
				require.Len(s.T(), rsRetrieved.Scope, 10) // 10 scopes were created for each role
				for _, s := range rsRetrieved.Scope {
					if s == rsDB.ResourceTypeScope.Name {
						foundCreatedRoleScope = true
					}
				}
			}
		}
		require.True(s.T(), foundCreatedRoleScope)
	}
}
