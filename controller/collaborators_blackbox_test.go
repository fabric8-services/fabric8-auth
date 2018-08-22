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

	testIdentity1 account.Identity
	testIdentity2 account.Identity
	testIdentity3 account.Identity
}

func (s *CollaboratorsControllerTestSuite) SetupTest() {
	s.DBTestSuite.SetupTest()
	// out of the 3 identities, have one with a user which has a private email.
	testIdentity, err := testsupport.CreateTestUser(s.DB, &testsupport.TestUserPrivate)
	require.Nil(s.T(), err)
	s.testIdentity1 = testIdentity
	testIdentity, err = testsupport.CreateTestIdentity(s.DB, "TestCollaborators-"+uuid.NewV4().String(), "TestCollaborators")
	require.Nil(s.T(), err)
	s.testIdentity2 = testIdentity
	testIdentity, err = testsupport.CreateTestIdentity(s.DB, "TestCollaborators-"+uuid.NewV4().String(), "TestCollaborators")
	require.Nil(s.T(), err)
	s.testIdentity3 = testIdentity
}

func (s *CollaboratorsControllerTestSuite) SecuredController() (*goa.Service, *CollaboratorsController) {
	svc := testsupport.ServiceAsUser("Collaborators-Service", s.testIdentity1)
	return svc, NewCollaboratorsController(svc, s.Application, s.Configuration)
}

func (s *CollaboratorsControllerTestSuite) SecuredControllerForIdentity(identity *account.Identity) (*goa.Service, *CollaboratorsController) {
	if identity == nil {
		return s.SecuredController()
	}
	svc := testsupport.ServiceAsUser("Collaborators-Service", *identity)
	return svc, NewCollaboratorsController(svc, s.Application, s.Configuration)
}

func (s *CollaboratorsControllerTestSuite) SecuredControllerWithServiceAccount(serviceAccount account.Identity) (*goa.Service, *CollaboratorsController) {
	svc := testsupport.ServiceAsServiceAccountUser("Token-Service", serviceAccount)
	return svc, NewCollaboratorsController(svc, s.Application, s.Configuration)
}

func (s *CollaboratorsControllerTestSuite) UnSecuredController() (*goa.Service, *CollaboratorsController) {
	svc := goa.New("Collaborators-Service")
	return svc, NewCollaboratorsController(svc, s.Application, s.Configuration)
}

func (s *CollaboratorsControllerTestSuite) UnSecuredControllerDeprovisionedUser() (*goa.Service, *CollaboratorsController) {
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
			admin := g.CreateUser()
			contr := g.CreateUser()
			space := g.CreateSpace().AddAdmin(admin).AddContributor(contr)
			// noise
			g.CreateSpace().AddAdmin(g.CreateUser()).AddContributor(g.CreateUser())
			svc, ctrl := s.SecuredControllerForIdentity(admin.Identity())
			spaceID, err := uuid.FromString(space.SpaceID())
			require.NoError(t, err)
			// when
			_, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
			// then
			checkCollaborators(t, []uuid.UUID{admin.IdentityID(), contr.IdentityID()}, actualUsers)
		})

		t.Run("private email", func(t *testing.T) {
			// given
			spaceID := s.createSpace(t)
			svc, ctrl := s.SecuredControllerWithServiceAccount(testsupport.TestNotificationIdentity)
			// when
			res, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
			// then
			assertResponseHeaders(t, res)
			checkPrivateCollaborators(t, []uuid.UUID{s.testIdentity1.ID}, actualUsers)
		})

		t.Run("with pagination", func(t *testing.T) {
			// given
			spaceID := s.createSpace(t)
			svc, ctrl := s.SecuredController()
			payload := &app.AddManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: s.testIdentity1.ID.String(), Type: idnType}, {ID: s.testIdentity2.ID.String(), Type: idnType}, {ID: s.testIdentity3.ID.String(), Type: idnType}}}
			test.AddManyCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, payload)

			t.Run("with offset=0 and limit=3", func(t *testing.T) {
				// given
				offset := "0"
				limit := 3
				// when
				res, allUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, &limit, &offset, nil, nil)
				// then
				checkCollaborators(t, []uuid.UUID{s.testIdentity1.ID, s.testIdentity2.ID, s.testIdentity3.ID}, allUsers)
				assertResponseHeaders(t, res)
			})

			t.Run("with offset=0 and limit=5", func(t *testing.T) {
				// given
				offset := "0"
				limit := 5
				// when
				res, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, &limit, &offset, nil, nil)
				// then
				checkCollaborators(t, []uuid.UUID{s.testIdentity1.ID, s.testIdentity2.ID, s.testIdentity3.ID}, actualUsers)
				assertResponseHeaders(t, res)
			})

			t.Run("with offset=1 and limit=1", func(t *testing.T) {
				// given
				offset := "1"
				limit := 1
				// when
				res, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, &limit, &offset, nil, nil)
				// then
				checkCollaborators(t, []uuid.UUID{s.testIdentity2.ID}, actualUsers)
				assertResponseHeaders(t, res)
			})

			t.Run("with offset=1 and limit=10", func(t *testing.T) {
				// given
				offset := "1"
				limit := 10
				// when
				res, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, &limit, &offset, nil, nil)
				// then
				checkCollaborators(t, []uuid.UUID{s.testIdentity2.ID, s.testIdentity3.ID}, actualUsers)
				assertResponseHeaders(t, res)
			})

			t.Run("offset=2 and limit=1", func(t *testing.T) {
				// given
				offset := "2"
				limit := 1
				// when
				res, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, &limit, &offset, nil, nil)
				// then
				checkCollaborators(t, []uuid.UUID{s.testIdentity3.ID}, actualUsers)
				assertResponseHeaders(t, res)
			})

			t.Run("offset=3 and limit=10", func(t *testing.T) {
				// given
				offset := "3"
				limit := 10
				// when
				res, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, &limit, &offset, nil, nil)
				// then
				checkCollaborators(t, []uuid.UUID{}, actualUsers)
				assertResponseHeaders(t, res)
			})
		})

		t.Run("conditional requests", func(t *testing.T) {

			t.Run("with expired if-modified-since header", func(t *testing.T) {
				// given
				g := s.NewTestGraph(t)
				admin := g.CreateUser()
				contr := g.CreateUser()
				space := g.CreateSpace().AddAdmin(admin).AddContributor(contr)

				// noise
				g.CreateSpace().AddAdmin(g.CreateUser()).AddContributor(g.CreateUser())

				svc, ctrl := s.SecuredControllerForIdentity(admin.Identity())
				spaceID, err := uuid.FromString(space.SpaceID())
				require.NoError(t, err)

				ifModifiedSince := app.ToHTTPTime(s.testIdentity1.User.UpdatedAt.Add(-1 * time.Hour))
				res, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, &ifModifiedSince, nil)
				checkCollaborators(t, []uuid.UUID{admin.IdentityID(), contr.IdentityID()}, actualUsers)
				assertResponseHeaders(t, res)
			})

			t.Run("with expired if-none-match header", func(t *testing.T) {
				// given
				g := s.NewTestGraph(t)
				admin := g.CreateUser()
				contr := g.CreateUser()
				space := g.CreateSpace().AddAdmin(admin).AddContributor(contr)
				// noise
				g.CreateSpace().AddAdmin(g.CreateUser()).AddContributor(g.CreateUser())
				svc, ctrl := s.SecuredControllerForIdentity(admin.Identity())
				spaceID, err := uuid.FromString(space.SpaceID())
				require.NoError(t, err)
				ifNoneMatch := "foo"
				res, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, &ifNoneMatch)
				checkCollaborators(t, []uuid.UUID{admin.IdentityID(), contr.IdentityID()}, actualUsers)
				assertResponseHeaders(t, res)
			})

			t.Run("with valid if-modified-since header", func(t *testing.T) {
				// given
				spaceID := s.createSpace(t)
				svc, ctrl := s.SecuredController()
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
				spaceID := s.createSpace(t)
				svc, ctrl := s.SecuredController()
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
			svc, ctrl := s.UnSecuredController()
			// when/then
			test.ListCollaboratorsNotFound(t, svc.Context, svc, ctrl, uuid.NewV4(), nil, nil, nil, nil)
		})
	})

	s.T().Run("", func(t *testing.T) {

	})

}

func (s *CollaboratorsControllerTestSuite) TestAddSingleCollaborator() {

	s.T().Run("ok", func(t *testing.T) {
		spaceID := s.createSpace(t)
		svc, ctrl := s.SecuredController()
		// when
		_, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		// then
		checkCollaborators(t, []uuid.UUID{s.testIdentity1.ID}, actualUsers)
		// given
		test.AddCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, s.testIdentity2.ID.String())
		// when
		_, actualUsers = test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		// then
		checkCollaborators(t, []uuid.UUID{s.testIdentity1.ID, s.testIdentity2.ID}, actualUsers)

		// try adding again, should still return OK
		test.AddCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, s.testIdentity2.ID.String())
	})

	s.T().Run("not found", func(t *testing.T) {
		// given
		svc, ctrl := s.SecuredController()
		// when/then
		test.AddCollaboratorsNotFound(t, svc.Context, svc, ctrl, uuid.NewV4(), uuid.NewV4().String())
	})

	s.T().Run("bad request", func(t *testing.T) {
		// given
		spaceID := s.createSpace(t)
		svc, ctrl := s.SecuredController()
		// when/then
		test.AddCollaboratorsBadRequest(t, svc.Context, svc, ctrl, spaceID, "wrongFormatID")
	})

	s.T().Run("unauthorized", func(t *testing.T) {

		t.Run("missing token", func(t *testing.T) {
			// given
			spaceID := s.createSpace(t)
			svc, ctrl := s.UnSecuredController()
			// when/then
			test.AddCollaboratorsUnauthorized(t, svc.Context, svc, ctrl, spaceID, s.testIdentity2.ID.String())

		})

		t.Run("deprovisionned user", func(t *testing.T) {
			// given
			spaceID := s.createSpace(t)
			svc, ctrl := s.UnSecuredControllerDeprovisionedUser()
			// when/then
			test.AddCollaboratorsUnauthorized(t, svc.Context, svc, ctrl, spaceID, s.testIdentity2.ID.String())

		})
	})

}

func (s *CollaboratorsControllerTestSuite) TestAddManyCollaborators() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		spaceID := s.createSpace(t)
		g := s.NewTestGraph(t)
		svc, ctrl := s.SecuredController()
		// when
		_, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		// then
		checkCollaborators(t, []uuid.UUID{s.testIdentity1.ID}, actualUsers)
		// given
		payload := &app.AddManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: s.testIdentity1.ID.String(), Type: idnType}, {ID: s.testIdentity2.ID.String(), Type: idnType}, {ID: s.testIdentity3.ID.String(), Type: idnType}}}
		test.AddManyCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, payload)
		// when
		_, actualUsers = test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		// then
		checkCollaborators(t, []uuid.UUID{s.testIdentity1.ID, s.testIdentity2.ID, s.testIdentity3.ID}, actualUsers)

		// If an identity is already a contibutor, do not bother.

		// given
		identity4 := g.CreateUser().Identity()
		payload = &app.AddManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: s.testIdentity1.ID.String(), Type: idnType}, {ID: s.testIdentity2.ID.String(), Type: idnType}, {ID: identity4.ID.String(), Type: idnType}}}
		test.AddManyCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, payload)

		// when
		_, actualUsers = test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		// then
		checkCollaborators(t, []uuid.UUID{s.testIdentity1.ID, s.testIdentity2.ID, s.testIdentity3.ID, identity4.ID}, actualUsers)
	})

	s.T().Run("not found", func(t *testing.T) {
		// given
		svc, ctrl := s.SecuredController()
		payload := &app.AddManyCollaboratorsPayload{Data: []*app.UpdateUserID{}}
		// when/then
		test.AddManyCollaboratorsNotFound(t, svc.Context, svc, ctrl, uuid.NewV4(), payload)
	})

	s.T().Run("bad request", func(t *testing.T) {
		// given
		spaceID := s.createSpace(t)
		svc, ctrl := s.SecuredController()
		payload := &app.AddManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: "wrongFormatID", Type: idnType}}}
		// when/then
		test.AddManyCollaboratorsBadRequest(t, svc.Context, svc, ctrl, spaceID, payload)
	})

	s.T().Run("unauthorized", func(t *testing.T) {

		t.Run("missing token", func(t *testing.T) {
			// given
			spaceID := s.createSpace(t)
			svc, ctrl := s.UnSecuredController()
			payload := &app.AddManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: s.testIdentity2.ID.String(), Type: idnType}}}
			// when/then
			test.AddManyCollaboratorsUnauthorized(t, svc.Context, svc, ctrl, spaceID, payload)
		})

		t.Run("deprovisionned user", func(t *testing.T) {
			// given
			spaceID := s.createSpace(t)
			svc, ctrl := s.UnSecuredControllerDeprovisionedUser()
			payload := &app.AddManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: s.testIdentity2.ID.String(), Type: idnType}}}
			// when/then
			test.AddManyCollaboratorsUnauthorized(t, svc.Context, svc, ctrl, spaceID, payload)
		})

	})

}

func (s *CollaboratorsControllerTestSuite) TestRemoveSingleCollaborator() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		spaceID := s.createSpace(t)
		svc, ctrl := s.SecuredController()
		addPayload := newAddManyCollaboratorsPayload(s.testIdentity1, s.testIdentity2, s.testIdentity3)
		test.AddManyCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, addPayload)
		_, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		checkCollaborators(t, []uuid.UUID{s.testIdentity1.ID, s.testIdentity2.ID, s.testIdentity3.ID}, actualUsers)
		// when
		test.RemoveCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, s.testIdentity2.ID.String())
		// then
		_, actualUsers = test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		checkCollaborators(t, []uuid.UUID{s.testIdentity1.ID, s.testIdentity3.ID}, actualUsers)
	})

	s.T().Run("unauthorized", func(t *testing.T) {

		t.Run("missing token", func(t *testing.T) {
			// given
			spaceID := s.createSpace(t)
			svc, ctrl := s.UnSecuredController()
			// when/then
			test.RemoveCollaboratorsUnauthorized(t, svc.Context, svc, ctrl, spaceID, s.testIdentity2.ID.String())
		})

		t.Run("deprovisionned user ", func(t *testing.T) {
			// given
			spaceID := s.createSpace(t)
			svc, ctrl := s.UnSecuredControllerDeprovisionedUser()
			// when/then
			test.RemoveCollaboratorsUnauthorized(t, svc.Context, svc, ctrl, spaceID, s.testIdentity2.ID.String())
		})
	})

	s.T().Run("forbidden", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		ownerIdentity := g.CreateUser().Identity()
		spaceID := s.createSpaceByIdentity(t, ownerIdentity)
		toRemoveIdentity := g.CreateUser().Identity()
		svc, ctrl := s.SecuredController()
		_, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		checkCollaborators(t, []uuid.UUID{ownerIdentity.ID}, actualUsers)
		currentIdentity := g.CreateUser().Identity()
		svc, ctrl = s.SecuredControllerForIdentity(currentIdentity)
		// 403 from Auth
		// We have to allow any OSIO user to list collaborators. See https://github.com/fabric8-services/fabric8-auth/pull/521 for details
		//test.ListCollaboratorsForbidden(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)

		// when
		payload := &app.AddManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: g.CreateUser().IdentityID().String(), Type: idnType}}}
		test.AddCollaboratorsForbidden(t, svc.Context, svc, ctrl, spaceID, g.CreateUser().IdentityID().String())
		test.AddManyCollaboratorsForbidden(t, svc.Context, svc, ctrl, spaceID, payload)
		rPayload := &app.RemoveManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: toRemoveIdentity.ID.String(), Type: idnType}}}
		test.RemoveManyCollaboratorsForbidden(t, svc.Context, svc, ctrl, spaceID, rPayload)
	})

	s.T().Run("bad request", func(t *testing.T) {

		t.Run("space owner", func(t *testing.T) {
			// given
			spaceID := s.createSpace(t)
			svc, ctrl := s.SecuredController()
			addPayload := newAddManyCollaboratorsPayload(s.testIdentity1)
			test.AddManyCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, addPayload)
			_, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
			checkCollaborators(t, []uuid.UUID{s.testIdentity1.ID}, actualUsers)
			// when/then
			test.RemoveCollaboratorsBadRequest(t, svc.Context, svc, ctrl, spaceID, s.testIdentity1.ID.String())
		})

		t.Run("wrong format", func(t *testing.T) {
			// given
			spaceID := s.createSpace(t)
			svc, ctrl := s.SecuredController()
			// when/then
			test.RemoveCollaboratorsBadRequest(t, svc.Context, svc, ctrl, spaceID, "wrongFormatID")
		})
	})

	s.T().Run("not found", func(t *testing.T) {
		// given
		svc, ctrl := s.SecuredController()
		test.RemoveCollaboratorsNotFound(t, svc.Context, svc, ctrl, uuid.NewV4(), uuid.NewV4().String())
	})
}

func (s *CollaboratorsControllerTestSuite) TestRemoveMultipleCollaborator() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		spaceID := s.createSpace(t)
		svc, ctrl := s.SecuredController()
		addPayload := newAddManyCollaboratorsPayload(s.testIdentity1, s.testIdentity2, s.testIdentity3)
		test.AddManyCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, addPayload)
		_, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
		checkCollaborators(t, []uuid.UUID{s.testIdentity1.ID, s.testIdentity2.ID, s.testIdentity3.ID}, actualUsers)
		payload := &app.RemoveManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: s.testIdentity2.ID.String(), Type: idnType}, {ID: s.testIdentity3.ID.String(), Type: idnType}}}
		// when/then
		test.RemoveManyCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, payload)
	})

	s.T().Run("bad request", func(t *testing.T) {

		t.Run("space owner", func(t *testing.T) {
			// given
			spaceID := s.createSpace(t)
			svc, ctrl := s.SecuredController()
			_, actualUsers := test.ListCollaboratorsOK(t, svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
			checkCollaborators(t, []uuid.UUID{s.testIdentity1.ID}, actualUsers)
			payload := &app.RemoveManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: s.testIdentity1.ID.String(), Type: idnType}}}
			// when/then
			test.RemoveManyCollaboratorsBadRequest(t, svc.Context, svc, ctrl, spaceID, payload)
		})

		t.Run("wrong format", func(t *testing.T) {
			// given
			spaceID := s.createSpace(t)
			svc, ctrl := s.SecuredController()
			payload := &app.RemoveManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: "wrongFormatID", Type: idnType}}}
			// when/then
			test.RemoveManyCollaboratorsBadRequest(t, svc.Context, svc, ctrl, spaceID, payload)
		})

	})

	s.T().Run("unauthorized", func(t *testing.T) {

		t.Run("missing token", func(t *testing.T) {
			// given
			spaceID := s.createSpace(t)
			svc, ctrl := s.UnSecuredController()
			payload := &app.RemoveManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: s.testIdentity2.ID.String(), Type: idnType}}}
			// when/then
			test.RemoveManyCollaboratorsUnauthorized(t, svc.Context, svc, ctrl, spaceID, payload)

		})

		t.Run("deprovisionned user", func(t *testing.T) {
			// given
			spaceID := s.createSpace(t)
			svc, ctrl := s.UnSecuredControllerDeprovisionedUser()
			payload := &app.RemoveManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: s.testIdentity2.ID.String(), Type: idnType}}}
			// when/then
			test.RemoveManyCollaboratorsUnauthorized(t, svc.Context, svc, ctrl, spaceID, payload)
		})
	})

	s.T().Run("not found", func(t *testing.T) {
		// given
		svc, ctrl := s.SecuredController()
		payload := &app.RemoveManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: uuid.NewV4().String(), Type: idnType}}}

		test.RemoveManyCollaboratorsNotFound(t, svc.Context, svc, ctrl, uuid.NewV4(), payload)
	})

}

func checkCollaborators(t *testing.T, expectedUserIDs []uuid.UUID, actualUsers *app.UserList) {
	t.Log("Checking collaborators: ")
	t.Log("  expecting: ")
	for i := range expectedUserIDs {
		t.Log("  -", expectedUserIDs[i])
	}
	t.Log("  got: ")
	require.NotNil(t, actualUsers, "No 'actualUsers' to compare with")
	require.NotNil(t, actualUsers.Data, "No 'actualUsers.Data' to compare with")
	for i := range actualUsers.Data {
		t.Log("  -", *actualUsers.Data[i].ID)
	}
	require.Len(t, actualUsers.Data, len(expectedUserIDs))
	for _, expID := range expectedUserIDs {
		found := false
		for _, act := range actualUsers.Data {
			require.NotNil(t, act.ID)
			if expID.String() == *act.ID {
				found = true
				// Private emails don't show up.
				if act.Attributes.EmailPrivate != nil && *act.Attributes.EmailPrivate {
					assert.Empty(t, *act.Attributes.Email)
				}
				break
			}
		}
		assert.True(t, found, "identity %s not found", expID.String())
	}
}

func newAddManyCollaboratorsPayload(ids ...account.Identity) *app.AddManyCollaboratorsPayload {
	result := &app.AddManyCollaboratorsPayload{
		Data: make([]*app.UpdateUserID, len(ids)),
	}
	for i, id := range ids {
		result.Data[i] = &app.UpdateUserID{ID: id.ID.String(), Type: idnType}
	}
	return result
}

func checkPrivateCollaborators(t *testing.T, expectedUserIDs []uuid.UUID, actualUsers *app.UserList) {
	for i, id := range expectedUserIDs {
		require.NotNil(t, actualUsers.Data[i].ID)
		require.Equal(t, id.String(), *actualUsers.Data[i].ID)
		assert.True(t, *actualUsers.Data[i].Attributes.EmailPrivate)
		require.NotEmpty(t, *actualUsers.Data[i].Attributes.Email)
	}
}

func (s *CollaboratorsControllerTestSuite) createSpace(t *testing.T) uuid.UUID {
	return s.createSpaceByIdentity(t, nil)
}

func (s *CollaboratorsControllerTestSuite) createSpaceByIdentity(t *testing.T, identity *account.Identity) uuid.UUID {
	// given
	svc, _ := s.SecuredControllerForIdentity(identity)
	spaceCtrl := NewSpaceController(svc, s.Application)
	require.NotNil(t, spaceCtrl)

	id := uuid.NewV4()
	test.CreateSpaceOK(t, svc.Context, svc, spaceCtrl, id)
	return id
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
