package service_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gopkg.in/h2non/gock.v1"
)

func TestChe(t *testing.T) {
	suite.Run(t, &TestCheSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

type TestCheSuite struct {
	gormtestsupport.DBTestSuite
}

func (s *TestCheSuite) TestDeleteUser() {
	defer gock.OffAll()
	gock.Observe(gock.DumpRequest)

	identity := s.Graph.CreateIdentity().Identity()
	tokenManager, err := manager.DefaultManager(s.Configuration)
	require.NoError(s.T(), err)
	tokenMatcher := gock.NewBasicMatcher()
	tokenMatcher.Add(func(req *http.Request, ereq *gock.Request) (bool, error) {
		h := req.Header.Get("Authorization")
		if strings.HasPrefix(h, "Bearer ") {
			token := h[len("Bearer "):]
			// parse the token and check the 'sub' claim
			tk, err := tokenManager.Parse(context.Background(), token)
			if err != nil {
				return false, err
			}
			if claims, ok := tk.Claims.(jwt.MapClaims); ok {
				return claims["sub"] == identity.ID.String(), nil
			}
		}
		return false, nil
	})

	s.Run("ok", func() {
		// given
		gock.New("http://localhost:8091").
			Delete(fmt.Sprintf("api/user/%s", identity.ID)).
			SetMatcher(tokenMatcher).
			Reply(204) // expect a `No Content` response
		// when
		err = s.Application.CheService().DeleteUser(s.Ctx, *identity)
		// then
		require.NoError(s.T(), err)
	})

	s.Run("404 ok", func() {
		// given
		gock.New("http://localhost:8091").
			Delete(fmt.Sprintf("api/user/%s", identity.ID)).
			SetMatcher(tokenMatcher).
			Reply(404) // expect a `No Content` response
		// when
		err = s.Application.CheService().DeleteUser(s.Ctx, *identity)
		// then
		require.NoError(s.T(), err)
	})

	s.Run("another error not ok", func() {
		// given
		gock.New("http://localhost:8091").
			Delete(fmt.Sprintf("api/user/%s", identity.ID)).
			SetMatcher(tokenMatcher).
			Reply(500) // expect a `No Content` response
		// when
		fmt.Println("!!!!!! test")
		err = s.Application.CheService().DeleteUser(s.Ctx, *identity)
		// then
		require.Error(s.T(), err)
		fmt.Println("!!!!!! test done")
	})
}
