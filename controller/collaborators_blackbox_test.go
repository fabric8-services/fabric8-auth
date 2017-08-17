package controller_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"context"

	token "github.com/dgrijalva/jwt-go"
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/auth"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormsupport/cleaner"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/space/authz"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	almtoken "github.com/fabric8-services/fabric8-auth/token"
	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	idnType = "identities"
)

type DummyPolicyManager struct {
	rest *TestCollaboratorsREST
}

type DummySpaceAuthzService struct {
	rest *TestCollaboratorsREST
}

func (s *DummySpaceAuthzService) Authorize(ctx context.Context, endpoint string, spaceID string) (bool, error) {
	jwtToken := goajwt.ContextJWT(ctx)
	if jwtToken == nil {
		return false, errors.NewUnauthorizedError("Missing token")
	}
	id := jwtToken.Claims.(token.MapClaims)["sub"].(string)
	return strings.Contains(s.rest.policy.Config.UserIDs, id), nil
}

func (s *DummySpaceAuthzService) Configuration() authz.AuthzConfiguration {
	return nil
}

func (m *DummyPolicyManager) GetPolicy(ctx context.Context, request *goa.RequestData, policyID string) (*auth.KeycloakPolicy, *string, error) {
	pat := ""
	return m.rest.policy, &pat, nil
}

func (m *DummyPolicyManager) UpdatePolicy(ctx context.Context, request *goa.RequestData, policy auth.KeycloakPolicy, pat string) error {
	return nil
}

func (m *DummyPolicyManager) AddUserToPolicy(p *auth.KeycloakPolicy, userID string) bool {
	return p.AddUserToPolicy(userID)
}

func (m *DummyPolicyManager) RemoveUserFromPolicy(p *auth.KeycloakPolicy, userID string) bool {
	return p.RemoveUserFromPolicy(userID)
}

type TestCollaboratorsREST struct {
	gormtestsupport.DBTestSuite

	db            *gormapplication.GormDB
	clean         func()
	policy        *auth.KeycloakPolicy
	testIdentity1 account.Identity
	testIdentity2 account.Identity
	testIdentity3 account.Identity
	spaceID       uuid.UUID
}

func TestRunCollaboratorsREST(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &TestCollaboratorsREST{DBTestSuite: gormtestsupport.NewDBTestSuite("../config.yaml")})
}

func (rest *TestCollaboratorsREST) SetupTest() {
	rest.db = gormapplication.NewGormDB(rest.DB)
	rest.clean = cleaner.DeleteCreatedEntities(rest.DB)

	rest.policy = &auth.KeycloakPolicy{
		Name:             "TestCollaborators-" + uuid.NewV4().String(),
		Type:             auth.PolicyTypeUser,
		Logic:            auth.PolicyLogicPossitive,
		DecisionStrategy: auth.PolicyDecisionStrategyUnanimous,
	}
	testIdentity, err := testsupport.CreateTestIdentity(rest.DB, "TestCollaborators-"+uuid.NewV4().String(), "TestCollaborators")
	require.Nil(rest.T(), err)
	rest.testIdentity1 = testIdentity
	testIdentity, err = testsupport.CreateTestIdentity(rest.DB, "TestCollaborators-"+uuid.NewV4().String(), "TestCollaborators")
	require.Nil(rest.T(), err)
	rest.testIdentity2 = testIdentity
	testIdentity, err = testsupport.CreateTestIdentity(rest.DB, "TestCollaborators-"+uuid.NewV4().String(), "TestCollaborators")
	require.Nil(rest.T(), err)
	rest.testIdentity3 = testIdentity
	rest.spaceID = rest.createSpace()
}

func (rest *TestCollaboratorsREST) TearDownTest() {
	rest.clean()
}

func (rest *TestCollaboratorsREST) SecuredController() (*goa.Service, *CollaboratorsController) {
	priv, _ := almtoken.ParsePrivateKey([]byte(almtoken.RSAPrivateKey))
	svc := testsupport.ServiceAsSpaceUser("Collaborators-Service", almtoken.NewManagerWithPrivateKey(priv), rest.testIdentity1, &DummySpaceAuthzService{rest})
	return svc, NewCollaboratorsController(svc, rest.db, rest.Configuration, &DummyPolicyManager{rest: rest})
}

func (rest *TestCollaboratorsREST) UnSecuredController() (*goa.Service, *CollaboratorsController) {
	svc := goa.New("Collaborators-Service")
	return svc, NewCollaboratorsController(svc, rest.db, rest.Configuration, &DummyPolicyManager{rest: rest})
}

func (rest *TestCollaboratorsREST) TestListCollaboratorsWithRandomSpaceIDNotFound() {
	// given
	svc, ctrl := rest.UnSecuredController()
	test.ListCollaboratorsNotFound(rest.T(), svc.Context, svc, ctrl, uuid.NewV4(), nil, nil, nil, nil)
}

func (rest *TestCollaboratorsREST) TestListCollaboratorsOK() {
	// given
	svc, ctrl := rest.UnSecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity2.ID.String())
	// when
	res, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	// then
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID, rest.testIdentity2.ID}, actualUsers)
	assertResponseHeaders(rest.T(), res)
	// given
	rest.policy.RemoveUserFromPolicy(rest.testIdentity2.ID.String())
	// when
	res, actualUsers = test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	// then
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID}, actualUsers)
	assertResponseHeaders(rest.T(), res)
}

func (rest *TestCollaboratorsREST) TestListCollaboratorsByPagesOK() {
	// given
	svc, ctrl := rest.UnSecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity2.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity3.ID.String())
	offset := "0"
	limit := 3
	// when
	res, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, &limit, &offset, nil, nil)
	// then
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID, rest.testIdentity2.ID, rest.testIdentity3.ID}, actualUsers)
	assertResponseHeaders(rest.T(), res)

	// given
	offset = "0"
	limit = 5
	// when
	res, actualUsers = test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, &limit, &offset, nil, nil)
	// then
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID, rest.testIdentity2.ID, rest.testIdentity3.ID}, actualUsers)
	assertResponseHeaders(rest.T(), res)

	// given
	offset = "1"
	limit = 1
	// when
	res, actualUsers = test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, &limit, &offset, nil, nil)
	// then
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity2.ID}, actualUsers)
	assertResponseHeaders(rest.T(), res)

	// given
	offset = "1"
	limit = 10
	// when
	res, actualUsers = test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, &limit, &offset, nil, nil)
	// then
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity2.ID, rest.testIdentity3.ID}, actualUsers)
	assertResponseHeaders(rest.T(), res)

	// given
	offset = "2"
	limit = 1
	// when
	res, actualUsers = test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, &limit, &offset, nil, nil)
	// then
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity3.ID}, actualUsers)
	assertResponseHeaders(rest.T(), res)

	// given
	offset = "3"
	limit = 10
	// when
	res, actualUsers = test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, &limit, &offset, nil, nil)
	// then
	rest.checkCollaborators([]uuid.UUID{}, actualUsers)
	assertResponseHeaders(rest.T(), res)
}

func (rest *TestCollaboratorsREST) TestListCollaboratorsOKUsingExpiredIfModifiedSinceHeader() {
	// given
	svc, ctrl := rest.UnSecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity2.ID.String())
	// when
	ifModifiedSince := app.ToHTTPTime(rest.testIdentity1.User.UpdatedAt.Add(-1 * time.Hour))
	res, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, &ifModifiedSince, nil)
	// then
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID, rest.testIdentity2.ID}, actualUsers)
	assertResponseHeaders(rest.T(), res)
}

func (rest *TestCollaboratorsREST) TestListCollaboratorsOKUsingExpiredIfNoneMatchHeader() {
	// given
	svc, ctrl := rest.UnSecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity2.ID.String())
	// when
	ifNoneMatch := "foo"
	res, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, &ifNoneMatch)
	// then
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID, rest.testIdentity2.ID}, actualUsers)
	assertResponseHeaders(rest.T(), res)
}

func (rest *TestCollaboratorsREST) TestListCollaboratorsNotModifiedUsingIfModifiedSinceHeader() {
	// given
	svc, ctrl := rest.UnSecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity2.ID.String())
	// when
	ifModifiedSince := app.ToHTTPTime(rest.testIdentity1.UpdatedAt)
	res := test.ListCollaboratorsNotModified(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, &ifModifiedSince, nil)
	// then
	assertResponseHeaders(rest.T(), res)
}

func (rest *TestCollaboratorsREST) TestListCollaboratorsNotModifiedUsingIfNoneMatchHeader() {
	// given
	svc, ctrl := rest.UnSecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity2.ID.String())
	// when
	ifNoneMatch := app.GenerateEntitiesTag([]app.ConditionalRequestEntity{
		rest.testIdentity1.User,
		rest.testIdentity2.User,
	})
	res := test.ListCollaboratorsNotModified(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, &ifNoneMatch)
	// then
	assertResponseHeaders(rest.T(), res)
}

func (rest *TestCollaboratorsREST) TestAddCollaboratorsWithRandomSpaceIDNotFound() {
	// given
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	svc, ctrl := rest.SecuredController()
	test.AddCollaboratorsNotFound(rest.T(), svc.Context, svc, ctrl, uuid.NewV4(), uuid.NewV4().String())
}

func (rest *TestCollaboratorsREST) TestAddManyCollaboratorsWithRandomSpaceIDNotFound() {
	// given
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	svc, ctrl := rest.SecuredController()
	payload := &app.AddManyCollaboratorsPayload{Data: []*app.UpdateUserID{}}
	test.AddManyCollaboratorsNotFound(rest.T(), svc.Context, svc, ctrl, uuid.NewV4(), payload)
}

func (rest *TestCollaboratorsREST) TestAddCollaboratorsWithWrongUserIDFormatReturnsBadRequest() {
	// given
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	svc, ctrl := rest.SecuredController()
	// when/then
	test.AddCollaboratorsBadRequest(rest.T(), svc.Context, svc, ctrl, rest.spaceID, "wrongFormatID")
}

func (rest *TestCollaboratorsREST) TestAddManyCollaboratorsWithWrongUserIDFormatReturnsBadRequest() {
	// given
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	svc, ctrl := rest.SecuredController()
	payload := &app.AddManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: "wrongFormatID", Type: idnType}}}
	// when/then
	test.AddManyCollaboratorsBadRequest(rest.T(), svc.Context, svc, ctrl, rest.spaceID, payload)
}

func (rest *TestCollaboratorsREST) TestAddCollaboratorsOk() {
	appl := gormapplication.NewGormDB(rest.DB)
	resource, err := appl.SpaceResources().LoadBySpace(context.Background(), &rest.spaceID)
	require.Nil(rest.T(), err)

	svc, ctrl := rest.SecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	// when
	_, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	// then
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID}, actualUsers)
	// given
	test.AddCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, rest.testIdentity2.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity2.ID.String())
	// when
	_, actualUsers = test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	// then
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID, rest.testIdentity2.ID}, actualUsers)

	updatedResource, err := appl.SpaceResources().LoadBySpace(context.Background(), &rest.spaceID)
	require.Nil(rest.T(), err)
	require.True(rest.T(), resource.UpdatedAt.Before(updatedResource.UpdatedAt))
}

func (rest *TestCollaboratorsREST) TestAddManyCollaboratorsOk() {
	//given
	appl := gormapplication.NewGormDB(rest.DB)
	resource, err := appl.SpaceResources().LoadBySpace(context.Background(), &rest.spaceID)
	require.Nil(rest.T(), err)
	svc, ctrl := rest.SecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	// when
	_, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	// then
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID}, actualUsers)
	// given
	payload := &app.AddManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: rest.testIdentity1.ID.String(), Type: idnType}, {ID: rest.testIdentity2.ID.String(), Type: idnType}, {ID: rest.testIdentity3.ID.String(), Type: idnType}}}
	test.AddManyCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, payload)
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity2.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity3.ID.String())
	// when
	_, actualUsers = test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	// then
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID, rest.testIdentity2.ID, rest.testIdentity3.ID}, actualUsers)
	updatedResource, err := appl.SpaceResources().LoadBySpace(context.Background(), &rest.spaceID)
	require.Nil(rest.T(), err)
	require.True(rest.T(), resource.UpdatedAt.Before(updatedResource.UpdatedAt))
}

func (rest *TestCollaboratorsREST) TestAddCollaboratorsUnauthorizedIfNoToken() {
	// given
	svc, ctrl := rest.UnSecuredController()
	// when/then
	test.AddCollaboratorsUnauthorized(rest.T(), svc.Context, svc, ctrl, rest.spaceID, rest.testIdentity2.ID.String())
}

func (rest *TestCollaboratorsREST) TestAddManyCollaboratorsUnauthorizedIfNoToken() {
	// given
	svc, ctrl := rest.UnSecuredController()
	payload := &app.AddManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: rest.testIdentity2.ID.String(), Type: idnType}}}
	// when/then
	test.AddManyCollaboratorsUnauthorized(rest.T(), svc.Context, svc, ctrl, rest.spaceID, payload)
}

func (rest *TestCollaboratorsREST) TestAddCollaboratorsUnauthorizedIfCurrentUserIsNotCollaborator() {
	// given
	svc, ctrl := rest.SecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity2.ID.String())
	// when
	_, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	// then
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity2.ID}, actualUsers)
	// when/then
	test.AddCollaboratorsUnauthorized(rest.T(), svc.Context, svc, ctrl, rest.spaceID, rest.testIdentity1.ID.String())
}

func (rest *TestCollaboratorsREST) TestAddManyCollaboratorsUnauthorizedIfCurrentUserIsNotCollaborator() {
	// given
	svc, ctrl := rest.SecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity2.ID.String())
	_, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity2.ID}, actualUsers)
	payload := &app.AddManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: rest.testIdentity1.ID.String(), Type: idnType}}}
	// when/then
	test.AddManyCollaboratorsUnauthorized(rest.T(), svc.Context, svc, ctrl, rest.spaceID, payload)
}

func (rest *TestCollaboratorsREST) TestRemoveCollaboratorsUnauthorizedIfNoToken() {
	// given
	svc, ctrl := rest.UnSecuredController()
	// when/then
	test.RemoveCollaboratorsUnauthorized(rest.T(), svc.Context, svc, ctrl, rest.spaceID, rest.testIdentity2.ID.String())
}

func (rest *TestCollaboratorsREST) TestRemoveManyCollaboratorsUnauthorizedIfNoToken() {
	// given
	svc, ctrl := rest.UnSecuredController()
	payload := &app.RemoveManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: rest.testIdentity2.ID.String(), Type: idnType}}}
	// when/then
	test.RemoveManyCollaboratorsUnauthorized(rest.T(), svc.Context, svc, ctrl, rest.spaceID, payload)
}

func (rest *TestCollaboratorsREST) TestRemoveCollaboratorsUnauthorizedIfCurrentUserIsNotCollaborator() {
	// given
	priv, _ := almtoken.ParsePrivateKey([]byte(almtoken.RSAPrivateKey))
	svc := testsupport.ServiceAsSpaceUser("Collaborators-Service", almtoken.NewManagerWithPrivateKey(priv), rest.testIdentity2, &DummySpaceAuthzService{rest})
	ctrl := NewCollaboratorsController(svc, rest.db, rest.Configuration, &DummyPolicyManager{rest: rest})
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	_, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID}, actualUsers)
	// when/then
	test.RemoveCollaboratorsUnauthorized(rest.T(), svc.Context, svc, ctrl, rest.spaceID, rest.testIdentity2.ID.String())
}

func (rest *TestCollaboratorsREST) TestRemoveManyCollaboratorsUnauthorizedIfCurrentUserIsNotCollaborator() {
	// given
	priv, _ := almtoken.ParsePrivateKey([]byte(almtoken.RSAPrivateKey))
	svc := testsupport.ServiceAsSpaceUser("Collaborators-Service", almtoken.NewManagerWithPrivateKey(priv), rest.testIdentity2, &DummySpaceAuthzService{rest})
	ctrl := NewCollaboratorsController(svc, rest.db, rest.Configuration, &DummyPolicyManager{rest: rest})
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	_, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID}, actualUsers)
	payload := &app.RemoveManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: rest.testIdentity2.ID.String(), Type: idnType}}}
	// when/then
	test.RemoveManyCollaboratorsUnauthorized(rest.T(), svc.Context, svc, ctrl, rest.spaceID, payload)
}

func (rest *TestCollaboratorsREST) TestRemoveCollaboratorsFailsIfTryToRemoveLastCollaborator() {
	// given
	svc, ctrl := rest.SecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	_, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID}, actualUsers)
	// when/then
	test.RemoveCollaboratorsBadRequest(rest.T(), svc.Context, svc, ctrl, rest.spaceID, rest.testIdentity1.ID.String())
}

func (rest *TestCollaboratorsREST) TestRemoveManyCollaboratorsFailsIfTryToRemoveLastCollaborator() {
	// given
	svc, ctrl := rest.SecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	_, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID}, actualUsers)
	payload := &app.RemoveManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: rest.testIdentity1.ID.String(), Type: idnType}}}
	// when/then
	test.RemoveManyCollaboratorsBadRequest(rest.T(), svc.Context, svc, ctrl, rest.spaceID, payload)
}

func (rest *TestCollaboratorsREST) TestRemoveCollaboratorsWithRandomSpaceIDNotFound() {
	// given
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	svc, ctrl := rest.SecuredController()
	test.RemoveCollaboratorsNotFound(rest.T(), svc.Context, svc, ctrl, uuid.NewV4(), uuid.NewV4().String())
}

func (rest *TestCollaboratorsREST) TestRemoveManyCollaboratorsWithRandomSpaceIDNotFound() {
	// given
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	svc, ctrl := rest.SecuredController()
	payload := &app.RemoveManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: uuid.NewV4().String(), Type: idnType}}}

	test.RemoveManyCollaboratorsNotFound(rest.T(), svc.Context, svc, ctrl, uuid.NewV4(), payload)
}

func (rest *TestCollaboratorsREST) TestRemoveCollaboratorsWithWrongUserIDFormatReturnsBadRequest() {
	// given
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	svc, ctrl := rest.SecuredController()
	// when/then
	test.RemoveCollaboratorsBadRequest(rest.T(), svc.Context, svc, ctrl, rest.spaceID, "wrongFormatID")
}

func (rest *TestCollaboratorsREST) TestRemoveManyCollaboratorsWithWrongUserIDFormatReturnsBadRequest() {
	// given
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	svc, ctrl := rest.SecuredController()
	payload := &app.RemoveManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: "wrongFormatID", Type: idnType}}}
	// when/then
	test.RemoveManyCollaboratorsBadRequest(rest.T(), svc.Context, svc, ctrl, rest.spaceID, payload)
}

func (rest *TestCollaboratorsREST) checkCollaborators(expectedUserIDs []uuid.UUID, actualUsers *app.UserList) {
	rest.T().Log("Checking collaborators: ")
	rest.T().Log("  expecting: ")
	for i := range expectedUserIDs {
		rest.T().Log("  -", expectedUserIDs[i])
	}
	rest.T().Log("  got: ")
	require.NotNil(rest.T(), actualUsers, "No 'actualUsers' to compare with")
	require.NotNil(rest.T(), actualUsers.Data, "No 'actualUsers.Data' to compare with")
	for i := range actualUsers.Data {
		rest.T().Log("  -", *actualUsers.Data[i].ID)
	}
	require.Equal(rest.T(), len(expectedUserIDs), len(actualUsers.Data))
	for i, id := range expectedUserIDs {
		require.NotNil(rest.T(), actualUsers.Data[i].ID)
		require.Equal(rest.T(), id.String(), *actualUsers.Data[i].ID)
	}
}

func (rest *TestCollaboratorsREST) TestRemoveCollaboratorsOk() {
	appl := gormapplication.NewGormDB(rest.DB)
	resource, err := appl.SpaceResources().LoadBySpace(context.Background(), &rest.spaceID)
	require.Nil(rest.T(), err)

	svc, ctrl := rest.SecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity2.ID.String())
	_, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID, rest.testIdentity2.ID}, actualUsers)
	// when/then
	test.RemoveCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, rest.testIdentity2.ID.String())

	updatedResource, err := appl.SpaceResources().LoadBySpace(context.Background(), &rest.spaceID)
	require.Nil(rest.T(), err)
	require.True(rest.T(), resource.UpdatedAt.Before(updatedResource.UpdatedAt))
}

func (rest *TestCollaboratorsREST) TestRemoveManyCollaboratorsOk() {
	// given
	appl := gormapplication.NewGormDB(rest.DB)
	resource, err := appl.SpaceResources().LoadBySpace(context.Background(), &rest.spaceID)
	require.Nil(rest.T(), err)

	svc, ctrl := rest.SecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity2.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity3.ID.String())
	_, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID, rest.testIdentity2.ID, rest.testIdentity3.ID}, actualUsers)
	payload := &app.RemoveManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: rest.testIdentity2.ID.String(), Type: idnType}, {ID: rest.testIdentity3.ID.String(), Type: idnType}}}
	// when/then
	test.RemoveManyCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, payload)

	updatedResource, err := appl.SpaceResources().LoadBySpace(context.Background(), &rest.spaceID)
	require.Nil(rest.T(), err)
	require.True(rest.T(), resource.UpdatedAt.Before(updatedResource.UpdatedAt))
}

func (rest *TestCollaboratorsREST) createSpace() uuid.UUID {
	// given
	svc, _ := rest.SecuredController()
	spaceCtrl := NewSpaceController(svc, rest.db, rest.Configuration, &DummyResourceManager{})
	require.NotNil(rest.T(), spaceCtrl)

	id := uuid.NewV4()
	test.CreateSpaceOK(rest.T(), svc.Context, svc, spaceCtrl, id)
	return id
}

type TestSpaceAuthzService struct {
	owner account.Identity
}

func (s *TestSpaceAuthzService) Authorize(ctx context.Context, endpoint string, spaceID string) (bool, error) {
	jwtToken := goajwt.ContextJWT(ctx)
	if jwtToken == nil {
		return false, errors.NewUnauthorizedError("Missing token")
	}
	id := jwtToken.Claims.(token.MapClaims)["sub"].(string)
	return s.owner.ID.String() == id, nil
}

func (s *TestSpaceAuthzService) Configuration() authz.AuthzConfiguration {
	return nil
}

func assertResponseHeaders(t *testing.T, res http.ResponseWriter) (string, string, string) {
	lastModified := res.Header()[app.LastModified]
	eTag := res.Header()[app.ETag]
	cacheControl := res.Header()[app.CacheControl]
	assert.NotEmpty(t, lastModified)
	assert.NotEmpty(t, eTag)
	assert.NotEmpty(t, cacheControl)
	return eTag[0], lastModified[0], cacheControl[0]
}

type DummyResourceManager struct {
	ResourceID   *string
	PermissionID *string
	PolicyID     *string
}

func (m *DummyResourceManager) CreateResource(ctx context.Context, request *goa.RequestData, name string, rType string, uri *string, scopes *[]string, userID string) (*auth.Resource, error) {
	if m.ResourceID == nil {
		return &auth.Resource{ResourceID: uuid.NewV4().String(), PermissionID: uuid.NewV4().String(), PolicyID: uuid.NewV4().String()}, nil
	}
	return &auth.Resource{ResourceID: *m.ResourceID, PermissionID: *m.PermissionID, PolicyID: *m.PolicyID}, nil
}

func (m *DummyResourceManager) DeleteResource(ctx context.Context, request *goa.RequestData, resource auth.Resource) error {
	return nil
}
