package controller_test

import (
	"net/http"
	"testing"
	"time"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	idnType = "identities"
)

func TestCollaboratorsController(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &CollaboratorsControllerTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

type CollaboratorsControllerTestSuite struct {
	gormtestsupport.DBTestSuite
}

func (s *CollaboratorsControllerTestSuite) NewSecuredController(identity *account.Identity) (*goa.Service, *CollaboratorsController) {
	svc := testsupport.ServiceAsUser("Collaborators-Service", *identity)
	return svc, NewCollaboratorsController(svc, s.Application, s.Configuration)
}

func (s *CollaboratorsControllerTestSuite) NewSecuredControllerWithServiceAccount(serviceAccount account.Identity) (*goa.Service, *CollaboratorsController) {
	svc := testsupport.ServiceAsServiceAccountUser("Token-Service", serviceAccount)
	return svc, NewCollaboratorsController(svc, s.Application, s.Configuration)
}

func (s *CollaboratorsControllerTestSuite) NewUnsecuredController() (*goa.Service, *CollaboratorsController) {
	svc := goa.New("Collaborators-Service")
	return svc, NewCollaboratorsController(svc, s.Application, s.Configuration)
}

func (s *CollaboratorsControllerTestSuite) NewUnsecuredControllerDeprovisionedUser() (*goa.Service, *CollaboratorsController) {
	identity, err := testsupport.CreateDeprovisionedTestIdentityAndUser(s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)
	svc := testsupport.ServiceAsUser("Collaborators-Service", identity)
	return svc, NewCollaboratorsController(svc, s.Application, s.Configuration)
}

func (s *CollaboratorsControllerTestSuite) TestListCollaborators() {

	s.T().Run("ok", func(t *testing.T) {

		t.Run("default", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			admin := g.CreateUser()   // email is not private
			contrib := g.CreateUser() // email is not private
			space := g.CreateSpace().AddAdmin(admin).AddContributor(contrib)
			// noise
			g.CreateSpace().AddAdmin(g.CreateUser()).AddContributor(g.CreateUser())
			svc, ctrl := s.NewSecuredController(admin.Identity())
			spaceID, err := uuid.FromString(space.SpaceID())
			require.NoError(t, err)
			// when
			res, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
			// then
			assertResponseHeaders(t, res)
			checkCollaborators(t, actualUsers, admin.Identity(), contrib.Identity())
		})

		t.Run("private email", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			admin := g.CreateUser(true)   // email is private
			contrib := g.CreateUser(true) // email is private
			space := g.CreateSpace().AddAdmin(admin).AddContributor(contrib)
			spaceID, _ := uuid.FromString(space.SpaceID())
			svc, ctrl := s.NewSecuredControllerWithServiceAccount(testsupport.TestNotificationIdentity)
			// when
			res, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
			// then
			assertResponseHeaders(t, res)
			checkCollaborators(t, actualUsers, admin.Identity(), contrib.Identity())
		})

		t.Run("with pagination", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			admin := g.CreateUser("admin")
			contrib := g.CreateUser("contrib")
			viewer := g.CreateUser("viewer")
			space := g.CreateSpace().AddAdmin(admin).AddContributor(contrib).AddViewer(viewer)
			spaceID, _ := uuid.FromString(space.SpaceID())
			svc, ctrl := s.NewSecuredController(admin.Identity())

			t.Run("with offset=0 and limit=3", func(t *testing.T) {
				// given
				offset := "0"
				limit := 3
				// when
				res, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, &limit, &offset, nil, nil)
				// then
				checkCollaborators(t, actualUsers, admin.Identity(), contrib.Identity()) // viewer user is not included, since she has no `collaborate` scope
				assertResponseHeaders(t, res)
			})

			t.Run("with offset=0 and limit=5", func(t *testing.T) {
				// given
				offset := "0"
				limit := 5
				// when
				res, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, &limit, &offset, nil, nil)
				// then
				checkCollaborators(t, actualUsers, admin.Identity(), contrib.Identity()) // viewer user is not included, since she has no `collaborate` scope
				assertResponseHeaders(t, res)
			})

			t.Run("with offset=1 and limit=1", func(t *testing.T) {
				// given
				offset := "1"
				limit := 1
				// when
				res, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, &limit, &offset, nil, nil)
				// then
				assertResponseHeaders(t, res)
				checkCollaborators(t, actualUsers, admin.Identity()) // because contributors are collected before admins, so 1st contrib is skipped from results page
			})

			t.Run("with offset=1 and limit=10", func(t *testing.T) {
				// given
				offset := "1"
				limit := 10
				// when
				res, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, &limit, &offset, nil, nil)
				// then
				assertResponseHeaders(t, res)
				checkCollaborators(t, actualUsers, admin.Identity()) // because contributors are collected before admins, so 1st contrib is skipped from results page
			})

			t.Run("offset=2 and limit=1", func(t *testing.T) {
				// given
				offset := "2"
				limit := 1
				// when
				res, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, &limit, &offset, nil, nil)
				// then
				assertResponseHeaders(t, res)
				checkCollaborators(t, actualUsers) // expect no result
			})

			t.Run("offset=3 and limit=10", func(t *testing.T) {
				// given
				offset := "3"
				limit := 10
				// when
				res, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, &limit, &offset, nil, nil)
				// then
				assert.Empty(t, actualUsers.Data)
				assertResponseHeaders(t, res) // expect no result either
			})
		})

		t.Run("conditional requests", func(t *testing.T) {

			t.Run("with expired if-modified-since header", func(t *testing.T) {
				// given
				g := s.NewTestGraph(t)
				// noise
				g.CreateSpace().AddAdmin(g.CreateUser()).AddContributor(g.CreateUser())
				// data
				admin := g.CreateUser()
				contrib := g.CreateUser()
				space := g.CreateSpace().AddAdmin(admin).AddContributor(contrib)
				svc, ctrl := s.NewSecuredController(admin.Identity())
				spaceID, err := uuid.FromString(space.SpaceID())
				require.NoError(t, err)
				// when
				ifModifiedSince := app.ToHTTPTime(time.Now().Add(-1 * time.Hour))
				res, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, &ifModifiedSince, nil)
				// then
				checkCollaborators(t, actualUsers, admin.Identity(), contrib.Identity())
				assertResponseHeaders(t, res)
			})

			t.Run("with expired if-none-match header", func(t *testing.T) {
				// given
				g := s.NewTestGraph(t)
				admin := g.CreateUser()
				contrib := g.CreateUser()
				space := g.CreateSpace().AddAdmin(admin).AddContributor(contrib)
				// noise
				g.CreateSpace().AddAdmin(g.CreateUser()).AddContributor(g.CreateUser())
				svc, ctrl := s.NewSecuredController(admin.Identity())
				spaceID, err := uuid.FromString(space.SpaceID())
				require.NoError(t, err)
				ifNoneMatch := "foo"
				// when
				res, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, &ifNoneMatch)
				// then
				checkCollaborators(t, actualUsers, admin.Identity(), contrib.Identity())
				assertResponseHeaders(t, res)
			})

			t.Run("with valid if-modified-since header", func(t *testing.T) {
				// given
				g := s.NewTestGraph(t)
				admin := g.CreateUser()
				contrib := g.CreateUser()
				space := g.CreateSpace().AddAdmin(admin).AddContributor(contrib)
				spaceID, _ := uuid.FromString(space.SpaceID())
				svc, ctrl := s.NewSecuredController(admin.Identity())
				res, _ := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
				lastModified, err := getHeader(res, app.LastModified)
				require.NoError(t, err)
				// when
				res = test.ListCollaboratorsNotModified(t, svc.Context, svc, ctrl, spaceID, nil, nil, lastModified, nil)
				// then
				assertResponseHeaders(t, res)
			})

			t.Run("with valid if-none-match header", func(t *testing.T) {
				// given
				g := s.NewTestGraph(t)
				admin := g.CreateUser()
				contrib := g.CreateUser()
				space := g.CreateSpace().AddAdmin(admin).AddContributor(contrib)
				spaceID, _ := uuid.FromString(space.SpaceID())
				svc, ctrl := s.NewSecuredController(admin.Identity())
				res, _ := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
				etag, err := getHeader(res, app.ETag)
				require.NoError(t, err)
				// when
				res = test.ListCollaboratorsNotModified(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, etag)
				// then
				assertResponseHeaders(t, res)
			})

		})
	})

	s.T().Run("not found", func(t *testing.T) {

		t.Run("random space id", func(t *testing.T) {
			// given
			svc, ctrl := s.NewUnsecuredController()
			// when/then
			test.ListCollaboratorsNotFound(t, svc.Context, svc, ctrl, uuid.NewV4(), nil, nil, nil, nil)
		})
	})

}

func (s *CollaboratorsControllerTestSuite) TestAddSingleCollaborator() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		admin := g.CreateUser()
		contrib := g.CreateUser()
		space := g.CreateSpace().AddAdmin(admin).AddContributor(contrib)
		spaceID, _ := uuid.FromString(space.SpaceID())
		svc, ctrl := s.NewSecuredController(admin.Identity())
		// when
		_, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		// then
		require.Len(t, actualUsers.Data, 2)
		assert.ElementsMatch(t,
			[]string{admin.IdentityID().String(), contrib.IdentityID().String()},
			[]string{*actualUsers.Data[0].ID, *actualUsers.Data[1].ID})
		// given
		extraUser := g.CreateUser()
		test.AddCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, extraUser.IdentityID().String())
		// when
		_, actualUsers = test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		// then
		checkCollaborators(t, actualUsers, admin.Identity(), contrib.Identity(), extraUser.Identity())
		// try adding again, should still return OK
		test.AddCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, extraUser.IdentityID().String())
	})

	s.T().Run("not found", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		admin := g.CreateUser()
		svc, ctrl := s.NewSecuredController(admin.Identity())
		// when/then
		test.AddCollaboratorsNotFound(t, svc.Context, svc, ctrl, uuid.NewV4(), uuid.NewV4().String())
	})

	s.T().Run("bad request", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		admin := g.CreateUser()
		contrib := g.CreateUser()
		space := g.CreateSpace().AddAdmin(admin).AddContributor(contrib)
		spaceID, _ := uuid.FromString(space.SpaceID())
		svc, ctrl := s.NewSecuredController(admin.Identity())
		// when/then
		test.AddCollaboratorsBadRequest(t, svc.Context, svc, ctrl, spaceID, "wrongFormatID")
	})

	s.T().Run("unauthorized", func(t *testing.T) {

		t.Run("missing token", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			admin := g.CreateUser()
			contrib := g.CreateUser()
			space := g.CreateSpace().AddAdmin(admin).AddContributor(contrib)
			spaceID, _ := uuid.FromString(space.SpaceID())
			svc, ctrl := s.NewUnsecuredController()
			extraUser := g.CreateUser()
			// when/then
			test.AddCollaboratorsUnauthorized(t, svc.Context, svc, ctrl, spaceID, extraUser.IdentityID().String())
		})

		t.Run("deprovisionned user", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			admin := g.CreateUser()
			contrib := g.CreateUser()
			space := g.CreateSpace().AddAdmin(admin).AddContributor(contrib)
			spaceID, _ := uuid.FromString(space.SpaceID())
			svc, ctrl := s.NewUnsecuredControllerDeprovisionedUser()
			extraUser := g.CreateUser()
			// when/then
			test.AddCollaboratorsUnauthorized(t, svc.Context, svc, ctrl, spaceID, extraUser.IdentityID().String())

		})
	})

}

func (s *CollaboratorsControllerTestSuite) TestAddManyCollaborators() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		admin := g.CreateUser()
		contrib := g.CreateUser()
		space := g.CreateSpace().AddAdmin(admin).AddContributor(contrib)
		spaceID, _ := uuid.FromString(space.SpaceID())
		svc, ctrl := s.NewSecuredController(admin.Identity())
		// when
		_, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		// then
		checkCollaborators(t, actualUsers, admin.Identity(), contrib.Identity())
		// given
		viewer1 := g.CreateUser()
		payload := newAddManyCollaboratorsPayload(t, admin.Identity(), contrib.Identity(), viewer1.Identity())
		test.AddManyCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, payload)
		// when
		_, actualUsers = test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		// then
		checkCollaborators(t, actualUsers, admin.Identity(), contrib.Identity(), viewer1.Identity())
		// If an identity already has a role, do not bother.
		// given
		viewer2 := g.CreateUser()
		payload = newAddManyCollaboratorsPayload(t, admin.Identity(), contrib.Identity(), viewer1.Identity(), viewer2.Identity())
		test.AddManyCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, payload)

		// when
		_, actualUsers = test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		// then
		checkCollaborators(t, actualUsers, admin.Identity(), contrib.Identity(), viewer1.Identity(), viewer2.Identity())
	})

	s.T().Run("not found", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		admin := g.CreateUser()
		svc, ctrl := s.NewSecuredController(admin.Identity())
		payload := newAddManyCollaboratorsPayload(t)
		// when/then
		test.AddManyCollaboratorsNotFound(t, svc.Context, svc, ctrl, uuid.NewV4(), payload)
	})

	s.T().Run("bad request", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		admin := g.CreateUser()
		space := g.CreateSpace().AddAdmin(admin)
		spaceID, _ := uuid.FromString(space.SpaceID())
		svc, ctrl := s.NewSecuredController(admin.Identity())
		payload := newAddManyCollaboratorsPayload(t, "foo")
		// when/then
		test.AddManyCollaboratorsBadRequest(t, svc.Context, svc, ctrl, spaceID, payload)
	})

	s.T().Run("unauthorized", func(t *testing.T) {

		t.Run("missing token", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			admin := g.CreateUser()
			space := g.CreateSpace()
			spaceID, _ := uuid.FromString(space.SpaceID())
			svc, ctrl := s.NewUnsecuredController()
			payload := newAddManyCollaboratorsPayload(t, admin.IdentityID())
			// when/then
			test.AddManyCollaboratorsUnauthorized(t, svc.Context, svc, ctrl, spaceID, payload)
		})

		t.Run("deprovisionned user", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			admin := g.CreateUser()
			space := g.CreateSpace()
			spaceID, _ := uuid.FromString(space.SpaceID())
			svc, ctrl := s.NewUnsecuredControllerDeprovisionedUser()
			payload := newAddManyCollaboratorsPayload(t, admin.IdentityID())
			// when/then
			test.AddManyCollaboratorsUnauthorized(t, svc.Context, svc, ctrl, spaceID, payload)
		})

	})

}

func (s *CollaboratorsControllerTestSuite) TestRemoveSingleCollaborator() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		admin := g.CreateUser()
		contrib := g.CreateUser()
		viewer := g.CreateUser()
		space := g.CreateSpace().AddAdmin(admin).AddContributor(contrib).AddViewer(viewer)
		spaceID, _ := uuid.FromString(space.SpaceID())
		svc, ctrl := s.NewSecuredController(admin.Identity())
		_, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		checkCollaborators(t, actualUsers, admin.Identity(), contrib.Identity()) // viewer user is not included, since she has no `collaborate` scope
		// when
		test.RemoveCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, contrib.IdentityID().String())
		// then
		_, actualUsers = test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		checkCollaborators(t, actualUsers, admin.Identity()) // viewer user is not included, since she has no `collaborate` scope
	})

	s.T().Run("unauthorized", func(t *testing.T) {

		t.Run("missing token", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			admin := g.CreateUser()
			contrib := g.CreateUser()
			space := g.CreateSpace().AddAdmin(admin).AddContributor(contrib)
			spaceID, _ := uuid.FromString(space.SpaceID())
			svc, ctrl := s.NewUnsecuredController()
			// when/then
			test.RemoveCollaboratorsUnauthorized(t, svc.Context, svc, ctrl, spaceID, contrib.IdentityID().String())
		})

		t.Run("deprovisionned user account", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			admin := g.CreateUser()
			contrib := g.CreateUser()
			space := g.CreateSpace().AddAdmin(admin).AddContributor(contrib)
			spaceID, _ := uuid.FromString(space.SpaceID())
			svc, ctrl := s.NewUnsecuredControllerDeprovisionedUser()
			// when/then
			test.RemoveCollaboratorsUnauthorized(t, svc.Context, svc, ctrl, spaceID, contrib.IdentityID().String())
		})
	})

	s.T().Run("forbidden", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		admin := g.CreateUser()
		space := g.CreateSpace().AddAdmin(admin)
		spaceID, _ := uuid.FromString(space.SpaceID())
		svc, ctrl := s.NewSecuredController(admin.Identity())
		_, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		checkCollaborators(t, actualUsers, admin.Identity())
		currentIdentity := g.CreateUser().Identity()
		svc, ctrl = s.NewSecuredController(currentIdentity)
		// 403 from Auth
		// We have to allow any OSIO user to list collaborators. See https://github.com/fabric8-services/fabric8-auth/pull/521 for details
		//test.ListCollaboratorsForbidden(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)

		t.Run("add", func(t *testing.T) {
			// when
			payload := newAddManyCollaboratorsPayload(t, g.CreateUser().Identity())
			// then
			test.AddCollaboratorsForbidden(t, svc.Context, svc, ctrl, spaceID, g.CreateUser().IdentityID().String())
			test.AddManyCollaboratorsForbidden(t, svc.Context, svc, ctrl, spaceID, payload)
		})

		t.Run("remove", func(t *testing.T) {
			// when
			payload := newRemoveManyCollaboratorsPayload(t, g.CreateUser().Identity())
			// then
			test.RemoveManyCollaboratorsForbidden(t, svc.Context, svc, ctrl, spaceID, payload)
		})

	})

	s.T().Run("bad request", func(t *testing.T) {

		t.Run("space owner", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			admin := g.CreateUser()
			space := g.CreateSpace().AddAdmin(admin)
			spaceID, _ := uuid.FromString(space.SpaceID())
			svc, ctrl := s.NewSecuredController(admin.Identity())
			addPayload := newAddManyCollaboratorsPayload(t, admin.Identity())
			test.AddManyCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, addPayload)
			_, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
			checkCollaborators(t, actualUsers, admin.Identity())
			// when/then
			test.RemoveCollaboratorsBadRequest(t, svc.Context, svc, ctrl, spaceID, admin.IdentityID().String())
		})

		t.Run("wrong format", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			admin := g.CreateUser()
			space := g.CreateSpace()
			spaceID, _ := uuid.FromString(space.SpaceID())
			svc, ctrl := s.NewSecuredController(admin.Identity())
			// when/then
			test.RemoveCollaboratorsBadRequest(t, svc.Context, svc, ctrl, spaceID, "wrongFormatID")
		})
	})

	s.T().Run("not found", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		admin := g.CreateUser()
		svc, ctrl := s.NewSecuredController(admin.Identity())
		test.RemoveCollaboratorsNotFound(t, svc.Context, svc, ctrl, uuid.NewV4(), uuid.NewV4().String())
	})
}

func (s *CollaboratorsControllerTestSuite) TestRemoveMultipleCollaborator() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		admin := g.CreateUser()
		contrib1 := g.CreateUser()
		contrib2 := g.CreateUser()
		space := g.CreateSpace().AddAdmin(admin).AddContributor(contrib1).AddContributor(contrib2)
		spaceID, _ := uuid.FromString(space.SpaceID())
		svc, ctrl := s.NewSecuredController(admin.Identity())
		_, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		checkCollaborators(t, actualUsers, admin.Identity(), contrib1.Identity(), contrib2.Identity())
		payload := newRemoveManyCollaboratorsPayload(t, contrib1.Identity(), contrib2.Identity())
		// when/then
		test.RemoveManyCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, payload)
	})

	s.T().Run("bad request", func(t *testing.T) {

		t.Run("space owner", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			admin := g.CreateUser()
			space := g.CreateSpace().AddAdmin(admin)
			spaceID, _ := uuid.FromString(space.SpaceID())
			svc, ctrl := s.NewSecuredController(admin.Identity())
			_, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
			checkCollaborators(t, actualUsers, admin.Identity())
			payload := newRemoveManyCollaboratorsPayload(t, admin.Identity())
			// when/then
			test.RemoveManyCollaboratorsBadRequest(t, svc.Context, svc, ctrl, spaceID, payload)
		})

		t.Run("wrong format", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			admin := g.CreateUser()
			space := g.CreateSpace()
			spaceID, _ := uuid.FromString(space.SpaceID())
			svc, ctrl := s.NewSecuredController(admin.Identity())
			payload := newRemoveManyCollaboratorsPayload(t, "foo")
			// when/then
			test.RemoveManyCollaboratorsBadRequest(t, svc.Context, svc, ctrl, spaceID, payload)
		})

	})

	s.T().Run("unauthorized", func(t *testing.T) {

		t.Run("missing token", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			admin := g.CreateUser()
			contrib := g.CreateUser()
			space := g.CreateSpace().AddAdmin(admin).AddContributor(contrib)
			spaceID, _ := uuid.FromString(space.SpaceID())
			svc, ctrl := s.NewUnsecuredController()
			payload := newRemoveManyCollaboratorsPayload(t, admin.Identity(), contrib.Identity())
			// when/then
			test.RemoveManyCollaboratorsUnauthorized(t, svc.Context, svc, ctrl, spaceID, payload)
		})

		t.Run("deprovisionned user", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			admin := g.CreateUser()
			contrib := g.CreateUser()
			space := g.CreateSpace().AddAdmin(admin).AddContributor(contrib)
			spaceID, _ := uuid.FromString(space.SpaceID())
			svc, ctrl := s.NewUnsecuredControllerDeprovisionedUser()
			payload := newRemoveManyCollaboratorsPayload(t, admin.Identity(), contrib.Identity())
			// when/then
			test.RemoveManyCollaboratorsUnauthorized(t, svc.Context, svc, ctrl, spaceID, payload)
		})
	})

	s.T().Run("not found", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		admin := g.CreateUser()
		svc, ctrl := s.NewSecuredController(admin.Identity())
		payload := &app.RemoveManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: uuid.NewV4().String(), Type: idnType}}}

		test.RemoveManyCollaboratorsNotFound(t, svc.Context, svc, ctrl, uuid.NewV4(), payload)
	})

}

func newAddManyCollaboratorsPayload(t *testing.T, ids ...interface{}) *app.AddManyCollaboratorsPayload {
	data := make([]*app.UpdateUserID, len(ids))
	for i, id := range ids {
		var v string
		switch id := id.(type) {
		case *account.Identity:
			v = id.ID.String()
		case uuid.UUID:
			v = id.String()
		case string:
			v = id
		default:
			t.Errorf("unsupported type of identity: %T", id)
		}
		data[i] = &app.UpdateUserID{
			ID:   v,
			Type: idnType,
		}
	}
	return &app.AddManyCollaboratorsPayload{
		Data: data,
	}
}

func newRemoveManyCollaboratorsPayload(t *testing.T, ids ...interface{}) *app.RemoveManyCollaboratorsPayload {
	data := make([]*app.UpdateUserID, len(ids))
	for i, id := range ids {
		var v string
		switch id := id.(type) {
		case *account.Identity:
			v = id.ID.String()
		case uuid.UUID:
			v = id.String()
		case string:
			v = id
		default:
			t.Errorf("unsupported type of identity: %T", id)
		}
		data[i] = &app.UpdateUserID{
			ID:   v,
			Type: idnType,
		}
	}
	return &app.RemoveManyCollaboratorsPayload{
		Data: data,
	}
}

func checkCollaborators(t *testing.T, actualUsers *app.UserList, expectedIdentities ...*account.Identity) {
	require.Len(t, actualUsers.Data, len(expectedIdentities))
	expectedIDs := make([]string, len(expectedIdentities))
	for i, data := range expectedIdentities {
		expectedIDs[i] = data.ID.String()
	}
	actualIDs := make([]string, len(actualUsers.Data))
	for i, data := range actualUsers.Data {
		require.NotNil(t, data.ID)
		actualIDs[i] = *data.ID
		require.NotEmpty(t, *data.Attributes.Email)
	}
	assert.ElementsMatch(t, actualIDs, expectedIDs)

}

func assertResponseHeaders(t *testing.T, res http.ResponseWriter) (string, string, string) {
	lastModified, err := getHeader(res, app.LastModified)
	require.NoError(t, err)
	eTag, err := getHeader(res, app.ETag)
	require.NoError(t, err)
	cacheControl, err := getHeader(res, app.CacheControl)
	require.NoError(t, err)
	return *eTag, *lastModified, *cacheControl
}
