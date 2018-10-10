package controller_test

import (
	"testing"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/authorization"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestResourceRolesController(t *testing.T) {
	suite.Run(t, &ResourceRolesControllerTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

type ResourceRolesControllerTestSuite struct {
	gormtestsupport.DBTestSuite
}

func (s *ResourceRolesControllerTestSuite) SetupSuite() {
	s.DBTestSuite.SetupSuite()
}

func (s *ResourceRolesControllerTestSuite) SecuredControllerWithIdentity(identity account.Identity) (*goa.Service, *ResourceRolesController) {
	svc := testsupport.ServiceAsUser("Resource-roles-Service", identity)
	return svc, NewResourceRolesController(svc, s.Application)
}

func (s *ResourceRolesControllerTestSuite) SecuredControllerWithIncompleteIdentity(identity account.Identity) (*goa.Service, *ResourceRolesController) {
	svc := testsupport.ServiceAsUserWithIncompleteClaims("Resource-roles-Service", identity)
	return svc, NewResourceRolesController(svc, s.Application)
}

func (s *ResourceRolesControllerTestSuite) UnsecuredController() (*goa.Service, *ResourceRolesController) {
	svc := testsupport.UnsecuredService("Resource-roles-Service")
	return svc, NewResourceRolesController(svc, s.Application)
}

func (s *ResourceRolesControllerTestSuite) TestListAssignedRoles() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		admin := g.CreateUser()
		viewer := g.CreateUser()
		space := g.CreateSpace().AddAdmin(admin).AddViewer(viewer)

		// noise
		g.CreateSpace().AddViewer(g.CreateUser())

		// Check available roles
		svc, ctrl := s.SecuredControllerWithIdentity(*viewer.Identity())
		_, returnedIdentityRoles := test.ListAssignedResourceRolesOK(t, svc.Context, svc, ctrl, space.SpaceID())
		require.Len(t, returnedIdentityRoles.Data, 2)
		s.checkExists(t, []uuid.UUID{admin.IdentityID(), viewer.IdentityID()}, []string{"admin", "viewer"}, returnedIdentityRoles)
	})

	s.T().Run("forbidden", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		svc, ctrl := s.SecuredControllerWithIdentity(*g.CreateUser().Identity())
		space := g.CreateSpace()
		test.ListAssignedResourceRolesForbidden(t, svc.Context, svc, ctrl, space.SpaceID())
	})

	s.T().Run("not found", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		svc, ctrl := s.SecuredControllerWithIdentity(*g.CreateUser().Identity())
		test.ListAssignedResourceRolesNotFound(t, svc.Context, svc, ctrl, uuid.NewV4().String())
	})

}

func (s *ResourceRolesControllerTestSuite) TestListAssignedRolesByRoleName() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		admin := g.CreateUser()
		viewer := g.CreateUser()
		space := g.CreateSpace().AddAdmin(admin).AddViewer(viewer)

		// noise
		g.CreateSpace().AddAdmin(g.CreateUser())

		// Check available roles
		svc, ctrl := s.SecuredControllerWithIdentity(*viewer.Identity())
		_, returnedIdentityRoles := test.ListAssignedByRoleNameResourceRolesOK(t, svc.Context, svc, ctrl, space.SpaceID(), "admin")
		require.Len(t, returnedIdentityRoles.Data, 1)
		s.checkExists(t, []uuid.UUID{admin.IdentityID()}, []string{"admin"}, returnedIdentityRoles)
	})

	s.T().Run("forbidden", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		svc, ctrl := s.SecuredControllerWithIdentity(*g.CreateUser().Identity())
		space := g.CreateSpace()
		test.ListAssignedByRoleNameResourceRolesForbidden(t, svc.Context, svc, ctrl, space.SpaceID(), authorization.SpaceViewerRole)
	})

	s.T().Run("not found", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		svc, ctrl := s.SecuredControllerWithIdentity(*g.CreateUser().Identity())
		test.ListAssignedByRoleNameResourceRolesNotFound(t, svc.Context, svc, ctrl, uuid.NewV4().String(), authorization.SpaceViewerRole)
	})

}

func (s *ResourceRolesControllerTestSuite) TestAssignRole() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		res := g.CreateSpace()

		var identitiesToBeAssigned []string
		for i := 0; i <= 10; i++ {
			testUser := g.CreateUser()
			res.AddViewer(testUser)
			identitiesToBeAssigned = append(identitiesToBeAssigned, testUser.Identity().ID.String())
		}

		roleAssignment := &app.AssignRoleData{Role: authorization.SpaceContributorRole, Ids: identitiesToBeAssigned}
		assignments := []*app.AssignRoleData{roleAssignment}

		// Create a user who has the privileges to assign roles
		adminUser := g.CreateUser("adminuser")
		res.AddAdmin(adminUser)

		svc, ctrl := s.SecuredControllerWithIdentity(*adminUser.Identity())
		payload := &app.AssignRoleResourceRolesPayload{
			Data: assignments,
		}

		test.AssignRoleResourceRolesNoContent(t, svc.Context, svc, ctrl, res.SpaceID(), payload)
	})

	s.T().Run("conflict", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		res := g.CreateSpace()

		testUser := g.CreateUser()
		res.AddViewer(testUser)

		// Create a user who has the privileges to assign roles
		adminUser := g.CreateUser("adminuser")
		res.AddAdmin(adminUser)

		svc, ctrl := s.SecuredControllerWithIdentity(*adminUser.Identity())
		payload := &app.AssignRoleResourceRolesPayload{
			Data: []*app.AssignRoleData{
				{
					Role: authorization.SpaceContributorRole,
					Ids:  []string{testUser.Identity().ID.String()},
				},
			},
		}

		test.AssignRoleResourceRolesNoContent(t, svc.Context, svc, ctrl, res.SpaceID(), payload)
		test.AssignRoleResourceRolesConflict(t, svc.Context, svc, ctrl, res.SpaceID(), payload)
	})

	s.T().Run("unauthorized", func(t *testing.T) {

		t.Run("incomplete claims", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			res := g.CreateSpace(g.ID("somespacename"))

			var identitiesToBeAssigned []*app.AssignRoleData
			for i := 0; i <= 2; i++ {
				identitiesToBeAssigned = append(identitiesToBeAssigned, &app.AssignRoleData{Role: authorization.SpaceContributorRole, Ids: []string{uuid.NewV4().String() + "#$%"}})
			}
			adminUser := g.CreateUser("adminuser")
			res.AddContributor(adminUser) //not really an admin

			svc, ctrl := s.SecuredControllerWithIncompleteIdentity(*adminUser.Identity())
			payload := &app.AssignRoleResourceRolesPayload{
				Data: identitiesToBeAssigned,
			}

			test.AssignRoleResourceRolesUnauthorized(t, svc.Context, svc, ctrl, res.SpaceID(), payload)
		})

		t.Run("missing data", func(t *testing.T) {
			svc, ctrl := s.UnsecuredController()
			payload := app.AssignRoleResourceRolesPayload{
				Data: []*app.AssignRoleData{},
			}
			test.AssignRoleResourceRolesUnauthorized(t, s.Ctx, svc, ctrl, uuid.NewV4().String(), &payload)
		})
	})

	s.T().Run("bad request", func(t *testing.T) {

		t.Run("invalid identity", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			res := g.CreateSpace(g.ID("somespacename"))

			var identitiesToBeAssigned []*app.AssignRoleData
			for i := 0; i <= 2; i++ {
				identitiesToBeAssigned = append(identitiesToBeAssigned, &app.AssignRoleData{Role: authorization.SpaceContributorRole, Ids: []string{uuid.NewV4().String() + "#$%"}})
			}

			// Create a user who has the privileges to assign roles
			adminUser := g.CreateUser("adminuser")
			res.AddAdmin(adminUser)

			svc, ctrl := s.SecuredControllerWithIdentity(*adminUser.Identity())
			payload := &app.AssignRoleResourceRolesPayload{
				Data: identitiesToBeAssigned,
			}

			test.AssignRoleResourceRolesBadRequest(t, svc.Context, svc, ctrl, res.SpaceID(), payload)
		})

		t.Run("user not in space", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			res := g.CreateSpace()

			var identitiesToBeAssigned []*app.AssignRoleData

			// some already have roles assigned
			for i := 0; i <= 2; i++ {
				testUser := g.CreateUser()
				identitiesToBeAssigned = append(identitiesToBeAssigned, &app.AssignRoleData{Role: authorization.SpaceContributorRole, Ids: []string{testUser.Identity().ID.String()}})
				res.AddViewer(testUser)
			}

			// while others don't have any role assigned.
			for i := 0; i <= 2; i++ {
				testUser := g.CreateUser()
				identitiesToBeAssigned = append(identitiesToBeAssigned, &app.AssignRoleData{Role: authorization.SpaceContributorRole, Ids: []string{testUser.Identity().ID.String()}})
			}

			// Create a user who has the privileges to assign roles
			adminUser := g.CreateUser("adminuser")
			res.AddAdmin(adminUser)

			svc, ctrl := s.SecuredControllerWithIdentity(*adminUser.Identity())
			payload := &app.AssignRoleResourceRolesPayload{
				Data: identitiesToBeAssigned,
			}

			test.AssignRoleResourceRolesBadRequest(t, svc.Context, svc, ctrl, res.SpaceID(), payload)
		})

	})

	s.T().Run("forbidden", func(t *testing.T) {

		t.Run("not allowed to assign roles", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			res := g.CreateSpace(g.ID("somespacename"))

			var identitiesToBeAssigned []*app.AssignRoleData
			for i := 0; i <= 2; i++ {
				testUser := g.CreateUser()
				res.AddViewer(testUser)
				identitiesToBeAssigned = append(identitiesToBeAssigned, &app.AssignRoleData{Role: authorization.SpaceContributorRole, Ids: []string{testUser.Identity().ID.String()}})
			}

			// Create a user who has the privileges to assign roles
			adminUser := g.CreateUser("adminuser")
			res.AddContributor(adminUser) //not really an admin

			svc, ctrl := s.SecuredControllerWithIdentity(*adminUser.Identity())
			payload := &app.AssignRoleResourceRolesPayload{
				Data: identitiesToBeAssigned,
			}

			test.AssignRoleResourceRolesForbidden(t, svc.Context, svc, ctrl, res.SpaceID(), payload)
		})
	})

}

func (s *ResourceRolesControllerTestSuite) TestListScopes() {

	s.T().Run("ok", func(t *testing.T) {

		t.Run("user has no role on space", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser(g.ID("m"))
			space := g.CreateSpace(g.ID("space")) // user has no role on this space
			svc, ctrl := s.SecuredControllerWithIdentity(*user.Identity())
			// when
			_, scopes := test.HasScopeResourceRolesOK(t, svc.Context, svc, ctrl, space.SpaceID(), authorization.ManageSpaceScope)
			// then
			require.NotNil(t, scopes)
			require.NotNil(t, scopes.Data)
			assert.Equal(t, scopes.Data.ScopeName, authorization.ManageSpaceScope)
			assert.Equal(t, scopes.Data.HasScope, false)
		})

		t.Run("user is admin on space", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser(g.ID("m"))
			space := g.CreateSpace(g.ID("space")).AddAdmin(user)
			svc, ctrl := s.SecuredControllerWithIdentity(*user.Identity())
			// when
			_, scopes := test.HasScopeResourceRolesOK(t, svc.Context, svc, ctrl, space.SpaceID(), authorization.ManageSpaceScope)
			// then
			require.NotNil(t, scopes)
			require.NotNil(t, scopes.Data)
			assert.Equal(t, scopes.Data.ScopeName, authorization.ManageSpaceScope)
			assert.Equal(t, scopes.Data.HasScope, true)
		})

		t.Run("user is in admin team on space", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser()
			team := g.CreateTeam().AddMember(user)
			space := g.CreateSpace().AddAdmin(team)
			svc, ctrl := s.SecuredControllerWithIdentity(*user.Identity())
			// when
			_, scopes := test.HasScopeResourceRolesOK(t, svc.Context, svc, ctrl, space.SpaceID(), authorization.ManageSpaceScope)
			// then
			require.NotNil(t, scopes)
			require.NotNil(t, scopes.Data)
			assert.Equal(t, scopes.Data.ScopeName, authorization.ManageSpaceScope)
			assert.Equal(t, scopes.Data.HasScope, true)
		})

		t.Run("user is in admin on space org with default role mapping", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser()
			team := g.CreateTeam().AddMember(user)
			org := g.CreateOrganization().AddAdmin(team)
			space := g.CreateSpace().AddAdmin(team)
			orgAdminRole := g.CreateRole(org.Resource().ResourceType)
			spaceContributorRole := g.CreateRole(space.Resource().ResourceType)
			spaceType := g.ResourceTypeByID(space.Resource().ResourceType.ResourceTypeID)
			g.CreateDefaultRoleMapping(spaceType, orgAdminRole, spaceContributorRole)
			svc, ctrl := s.SecuredControllerWithIdentity(*user.Identity())
			// when
			_, scopes := test.HasScopeResourceRolesOK(t, svc.Context, svc, ctrl, space.SpaceID(), authorization.ManageSpaceScope)
			// then
			require.NotNil(t, scopes)
			require.NotNil(t, scopes.Data)
			assert.Equal(t, scopes.Data.ScopeName, authorization.ManageSpaceScope)
			assert.Equal(t, scopes.Data.HasScope, true)
		})

		t.Run("user is in admin on space org with custom role mapping", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser()
			team := g.CreateTeam().AddMember(user)
			org := g.CreateOrganization().AddAdmin(team)
			space := g.CreateSpace().AddAdmin(team)
			orgAdminRole := g.RoleByNameAndResourceType(authorization.OrganizationAdminRole, org.Resource().ResourceType.Name)
			spaceContributorRole := g.RoleByNameAndResourceType(authorization.SpaceContributorRole, space.Resource().ResourceType.Name)
			g.CreateRoleMapping(space, orgAdminRole, spaceContributorRole)
			svc, ctrl := s.SecuredControllerWithIdentity(*user.Identity())
			// when
			_, scopes := test.HasScopeResourceRolesOK(t, svc.Context, svc, ctrl, space.SpaceID(), authorization.ManageSpaceScope)
			// then
			require.NotNil(t, scopes)
			require.NotNil(t, scopes.Data)
			assert.Equal(t, scopes.Data.ScopeName, authorization.ManageSpaceScope)
			assert.Equal(t, scopes.Data.HasScope, true)
		})

	})

	s.T().Run("unauthorized", func(t *testing.T) {

		t.Run("missing token", func(t *testing.T) {
			// given
			svc, ctrl := s.UnsecuredController()
			// when/then
			test.HasScopeResourceRolesUnauthorized(t, svc.Context, svc, ctrl, "", authorization.ManageSpaceScope)
		})
	})

	s.T().Run("not found", func(t *testing.T) {

		t.Run("resource does not exist", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser()
			svc, ctrl := s.SecuredControllerWithIdentity(*user.Identity())
			// when/then
			test.HasScopeResourceRolesNotFound(t, svc.Context, svc, ctrl, "foo", authorization.ManageSpaceScope)
		})
	})

}

func (s *ResourceRolesControllerTestSuite) checkExists(t *testing.T, identities []uuid.UUID, roleNames []string, pool *app.Identityroles) {
	for _, retrievedRole := range pool.Data {
		var foundUser bool
		for i, idn := range identities {
			foundUser = idn.String() == retrievedRole.AssigneeID && retrievedRole.RoleName == roleNames[i]
			if foundUser {
				break
			}
		}
		require.True(t, foundUser)
	}
}

func (s *ResourceRolesControllerTestSuite) compare(t *testing.T, createdRole role.IdentityRole, retrievedRole app.IdentityRolesData, isInherited bool) bool {
	require.Equal(t, createdRole.IdentityID.String(), retrievedRole.AssigneeID)
	require.Equal(t, createdRole.Role.Name, retrievedRole.RoleName)
	require.Equal(t, "user", retrievedRole.AssigneeType)
	if isInherited {
		require.True(t, retrievedRole.Inherited)
		require.NotNil(t, createdRole.Resource.ParentResourceID)
		require.Equal(t, *createdRole.Resource.ParentResourceID, *createdRole.Resource.ParentResourceID)
	} else {
		require.False(t, retrievedRole.Inherited)
	}
	return true
}
