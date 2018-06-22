package controller_test

import (
	"strings"
	"testing"
	"time"

	"context"

	"fmt"
	token "github.com/dgrijalva/jwt-go"
	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/auth"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/space/authz"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"net/http"
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

	policy        *auth.KeycloakPolicy
	testIdentity1 account.Identity
	testIdentity2 account.Identity
	testIdentity3 account.Identity
	spaceID       uuid.UUID
}

func TestRunCollaboratorsREST(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &TestCollaboratorsREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestCollaboratorsREST) SetupTest() {
	rest.DBTestSuite.SetupTest()
	rest.policy = &auth.KeycloakPolicy{
		Name:             "TestCollaborators-" + uuid.NewV4().String(),
		Type:             auth.PolicyTypeUser,
		Logic:            auth.PolicyLogicPossitive,
		DecisionStrategy: auth.PolicyDecisionStrategyUnanimous,
	}

	// out of the 3 identities, have one with a user which has a private email.
	testIdentity, err := testsupport.CreateTestUser(rest.DB, &testsupport.TestUserPrivate)
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

func (rest *TestCollaboratorsREST) SecuredController() (*goa.Service, *CollaboratorsController) {
	svc := testsupport.ServiceAsSpaceUser("Collaborators-Service", rest.testIdentity1, &DummySpaceAuthzService{rest})
	return svc, NewCollaboratorsController(svc, rest.Application, rest.Configuration, &DummyPolicyManager{rest: rest})
}

func (rest *TestCollaboratorsREST) SecuredControllerForIdentity(identity *account.Identity) (*goa.Service, *CollaboratorsController) {
	if identity == nil {
		return rest.SecuredController()
	}
	svc := testsupport.ServiceAsSpaceUser("Collaborators-Service", *identity, &DummySpaceAuthzService{rest})
	return svc, NewCollaboratorsController(svc, rest.Application, rest.Configuration, &DummyPolicyManager{rest: rest})
}

func (rest *TestCollaboratorsREST) SecuredControllerWithServiceAccount(serviceAccount account.Identity) (*goa.Service, *CollaboratorsController) {
	svc := testsupport.ServiceAsServiceAccountUser("Token-Service", serviceAccount)
	return svc, NewCollaboratorsController(svc, rest.Application, rest.Configuration, &DummyPolicyManager{rest: rest})
}

func (rest *TestCollaboratorsREST) UnSecuredController() (*goa.Service, *CollaboratorsController) {
	svc := goa.New("Collaborators-Service")
	return svc, NewCollaboratorsController(svc, rest.Application, rest.Configuration, &DummyPolicyManager{rest: rest})
}

func (rest *TestCollaboratorsREST) UnSecuredControllerDeprovisionedUser() (*goa.Service, *CollaboratorsController) {
	identity, err := testsupport.CreateDeprovisionedTestIdentityAndUser(rest.DB, uuid.NewV4().String())
	require.NoError(rest.T(), err)

	svc := testsupport.ServiceAsSpaceUser("Collaborators-Service", identity, &DummySpaceAuthzService{rest})
	return svc, NewCollaboratorsController(svc, rest.Application, rest.Configuration, &DummyPolicyManager{rest: rest})
}

func (rest *TestCollaboratorsREST) TestListCollaboratorsWithRandomSpaceIDNotFound() {
	// given
	svc, ctrl := rest.UnSecuredController()
	test.ListCollaboratorsNotFound(rest.T(), svc.Context, svc, ctrl, uuid.NewV4(), nil, nil, nil, nil)
}

func (rest *TestCollaboratorsREST) TestListCollaboratorsOK() {
	admin := rest.Graph.CreateUser()
	contr := rest.Graph.CreateUser()
	space := rest.Graph.CreateSpace().AddAdmin(admin).AddContributor(contr)

	// noise
	rest.Graph.CreateSpace().AddAdmin(rest.Graph.CreateUser()).AddContributor(rest.Graph.CreateUser())

	svc, ctrl := rest.SecuredControllerForIdentity(admin.Identity())
	spaceID, err := uuid.FromString(space.SpaceID())
	require.NoError(rest.T(), err)
	_, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
	rest.checkCollaborators([]uuid.UUID{admin.IdentityID(), contr.IdentityID()}, actualUsers)
}

func (rest *TestCollaboratorsREST) TestListCollaboratorsPrivateEmailsOK() {
	// given
	svc, ctrl := rest.SecuredControllerWithServiceAccount(testsupport.TestNotificationIdentity)
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	// when
	res, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	// then
	assertResponseHeaders(rest.T(), res)
	rest.checkPrivateCollaborators([]uuid.UUID{rest.testIdentity1.ID}, actualUsers)
}

func (rest *TestCollaboratorsREST) TestListCollaboratorsByPagesOK() {
	// given
	svc, ctrl := rest.SecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity2.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity3.ID.String())
	payload := &app.AddManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: rest.testIdentity1.ID.String(), Type: idnType}, {ID: rest.testIdentity2.ID.String(), Type: idnType}, {ID: rest.testIdentity3.ID.String(), Type: idnType}}}
	test.AddManyCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, payload)
	offset := "0"
	limit := 3
	// when
	res, allUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, &limit, &offset, nil, nil)
	// then
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID, rest.testIdentity2.ID, rest.testIdentity3.ID}, allUsers)
	assertResponseHeaders(rest.T(), res)

	// given
	offset = "0"
	limit = 5
	// when
	res, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, &limit, &offset, nil, nil)
	// then
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID, rest.testIdentity2.ID, rest.testIdentity3.ID}, actualUsers)
	assertResponseHeaders(rest.T(), res)

	fmt.Println("!!!!!!!!!!!!!")
	// given
	offset = "1"
	limit = 1
	// when
	res, actualUsers = test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, &limit, &offset, nil, nil)
	// then
	id1, err := uuid.FromString(*allUsers.Data[1].ID)
	require.NoError(rest.T(), err)
	id2, err := uuid.FromString(*allUsers.Data[2].ID)
	require.NoError(rest.T(), err)
	rest.checkCollaborators([]uuid.UUID{id1}, actualUsers)
	assertResponseHeaders(rest.T(), res)

	// given
	offset = "1"
	limit = 10
	// when
	res, actualUsers = test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, &limit, &offset, nil, nil)
	// then
	rest.checkCollaborators([]uuid.UUID{id1, id2}, actualUsers)
	assertResponseHeaders(rest.T(), res)

	// given
	offset = "2"
	limit = 1
	// when
	res, actualUsers = test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, &limit, &offset, nil, nil)
	// then
	rest.checkCollaborators([]uuid.UUID{id2}, actualUsers)
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
	admin := rest.Graph.CreateUser()
	contr := rest.Graph.CreateUser()
	space := rest.Graph.CreateSpace().AddAdmin(admin).AddContributor(contr)

	// noise
	rest.Graph.CreateSpace().AddAdmin(rest.Graph.CreateUser()).AddContributor(rest.Graph.CreateUser())

	svc, ctrl := rest.SecuredControllerForIdentity(admin.Identity())
	spaceID, err := uuid.FromString(space.SpaceID())
	require.NoError(rest.T(), err)

	ifModifiedSince := app.ToHTTPTime(rest.testIdentity1.User.UpdatedAt.Add(-1 * time.Hour))
	res, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, spaceID, nil, nil, &ifModifiedSince, nil)
	rest.checkCollaborators([]uuid.UUID{admin.IdentityID(), contr.IdentityID()}, actualUsers)
	assertResponseHeaders(rest.T(), res)
}

func (rest *TestCollaboratorsREST) TestListCollaboratorsOKUsingExpiredIfNoneMatchHeader() {
	admin := rest.Graph.CreateUser()
	contr := rest.Graph.CreateUser()
	space := rest.Graph.CreateSpace().AddAdmin(admin).AddContributor(contr)

	// noise
	rest.Graph.CreateSpace().AddAdmin(rest.Graph.CreateUser()).AddContributor(rest.Graph.CreateUser())

	svc, ctrl := rest.SecuredControllerForIdentity(admin.Identity())
	spaceID, err := uuid.FromString(space.SpaceID())
	require.NoError(rest.T(), err)

	ifNoneMatch := "foo"
	res, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, spaceID, nil, nil, nil, &ifNoneMatch)
	rest.checkCollaborators([]uuid.UUID{admin.IdentityID(), contr.IdentityID()}, actualUsers)
	assertResponseHeaders(rest.T(), res)
}

func (rest *TestCollaboratorsREST) TestListCollaboratorsNotModifiedUsingIfModifiedSinceHeader() {
	// given
	svc, ctrl := rest.SecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity2.ID.String())
	res, _ := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	lastModified, err := getHeader(res, app.LastModified)
	require.NoError(rest.T(), err)
	// when
	res = test.ListCollaboratorsNotModified(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, lastModified, nil)
	// then
	assertResponseHeaders(rest.T(), res)
}

func (rest *TestCollaboratorsREST) TestListCollaboratorsNotModifiedUsingIfNoneMatchHeader() {
	// given
	svc, ctrl := rest.SecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity2.ID.String())
	res, _ := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	etag, err := getHeader(res, app.ETag)
	require.NoError(rest.T(), err)
	// when
	res = test.ListCollaboratorsNotModified(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, etag)
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
	resource, err := rest.Application.SpaceResources().LoadBySpace(context.Background(), &rest.spaceID)
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

	updatedResource, err := rest.Application.SpaceResources().LoadBySpace(context.Background(), &rest.spaceID)
	require.Nil(rest.T(), err)
	require.True(rest.T(), resource.UpdatedAt.Before(updatedResource.UpdatedAt))
}

func (rest *TestCollaboratorsREST) TestAddManyCollaboratorsOk() {
	//given
	resource, err := rest.Application.SpaceResources().LoadBySpace(context.Background(), &rest.spaceID)
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
	updatedResource, err := rest.Application.SpaceResources().LoadBySpace(context.Background(), &rest.spaceID)
	require.Nil(rest.T(), err)
	require.True(rest.T(), resource.UpdatedAt.Before(updatedResource.UpdatedAt))
}

func (rest *TestCollaboratorsREST) TestAddCollaboratorsUnauthorizedIfNoToken() {
	// given
	svc, ctrl := rest.UnSecuredController()
	// when/then
	test.AddCollaboratorsUnauthorized(rest.T(), svc.Context, svc, ctrl, rest.spaceID, rest.testIdentity2.ID.String())
}

func (rest *TestCollaboratorsREST) TestAddCollaboratorsUnauthorizedWithDeprovisionedUser() {
	// given
	svc, ctrl := rest.UnSecuredControllerDeprovisionedUser()
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

func (rest *TestCollaboratorsREST) TestAddManyCollaboratorsUnauthorizedWithDeprovisionedUser() {
	// given
	svc, ctrl := rest.UnSecuredControllerDeprovisionedUser()
	payload := &app.AddManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: rest.testIdentity2.ID.String(), Type: idnType}}}
	// when/then
	test.AddManyCollaboratorsUnauthorized(rest.T(), svc.Context, svc, ctrl, rest.spaceID, payload)
}

func (rest *TestCollaboratorsREST) TestManageCollaboratorsFailsIfCurrentUserLacksPermissions() {

	ownerIdentity := rest.Graph.CreateUser().Identity()
	spaceID := rest.createSpaceByIdentity(ownerIdentity)
	toRemoveIdentity := rest.Graph.CreateUser().Identity()
	rest.policy.AddUserToPolicy(ownerIdentity.ID.String())
	rest.policy.AddUserToPolicy(toRemoveIdentity.ID.String())

	svc, ctrl := rest.SecuredControllerForIdentity(ownerIdentity)
	_, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
	rest.checkCollaborators([]uuid.UUID{ownerIdentity.ID}, actualUsers)

	currentIdentity := rest.Graph.CreateUser().Identity()
	svc, ctrl = rest.SecuredControllerForIdentity(currentIdentity)

	// 401 from Keycloak
	test.AddCollaboratorsUnauthorized(rest.T(), svc.Context, svc, ctrl, spaceID, rest.Graph.CreateUser().IdentityID().String())
	payload := &app.AddManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: rest.Graph.CreateUser().IdentityID().String(), Type: idnType}}}
	test.AddManyCollaboratorsUnauthorized(rest.T(), svc.Context, svc, ctrl, spaceID, payload)
	test.RemoveCollaboratorsUnauthorized(rest.T(), svc.Context, svc, ctrl, spaceID, toRemoveIdentity.ID.String())

	// 403 from Auth

	// We have to allow any OSIO user to list collaborators. See https://github.com/fabric8-services/fabric8-auth/pull/521 for details
	//test.ListCollaboratorsForbidden(rest.T(), svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)
	test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, spaceID, nil, nil, nil, nil)

	rest.policy.AddUserToPolicy(currentIdentity.ID.String()) // Add to KC policy to bypass KC authZ
	test.AddCollaboratorsForbidden(rest.T(), svc.Context, svc, ctrl, spaceID, rest.Graph.CreateUser().IdentityID().String())
	test.AddManyCollaboratorsForbidden(rest.T(), svc.Context, svc, ctrl, spaceID, payload)
	rPayload := &app.RemoveManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: toRemoveIdentity.ID.String(), Type: idnType}}}
	test.RemoveManyCollaboratorsForbidden(rest.T(), svc.Context, svc, ctrl, spaceID, rPayload)
}

func (rest *TestCollaboratorsREST) TestRemoveCollaboratorsUnauthorizedIfNoToken() {
	// given
	svc, ctrl := rest.UnSecuredController()
	// when/then
	test.RemoveCollaboratorsUnauthorized(rest.T(), svc.Context, svc, ctrl, rest.spaceID, rest.testIdentity2.ID.String())
}

func (rest *TestCollaboratorsREST) TestRemoveCollaboratorsUnauthorizedDeprovisionedUser() {
	// given
	svc, ctrl := rest.UnSecuredControllerDeprovisionedUser()
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

func (rest *TestCollaboratorsREST) TestRemoveManyCollaboratorsUnauthorizedDeprovisionedUser() {
	// given
	svc, ctrl := rest.UnSecuredControllerDeprovisionedUser()
	payload := &app.RemoveManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: rest.testIdentity2.ID.String(), Type: idnType}}}
	// when/then
	test.RemoveManyCollaboratorsUnauthorized(rest.T(), svc.Context, svc, ctrl, rest.spaceID, payload)
}

func (rest *TestCollaboratorsREST) TestRemoveCollaboratorsFailsIfTryToRemoveSpaceOwner() {
	// given
	svc, ctrl := rest.SecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	_, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID}, actualUsers)
	// when/then
	test.RemoveCollaboratorsBadRequest(rest.T(), svc.Context, svc, ctrl, rest.spaceID, rest.testIdentity1.ID.String())
}

func (rest *TestCollaboratorsREST) TestRemoveManyCollaboratorsFailsIfTryToRemoveSpaceOwner() {
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
	for _, expID := range expectedUserIDs {
		found := false
		for _, act := range actualUsers.Data {
			require.NotNil(rest.T(), act.ID)
			if expID.String() == *act.ID {
				found = true
				// Private emails don't show up.
				if act.Attributes.EmailPrivate != nil && *act.Attributes.EmailPrivate {
					assert.Empty(rest.T(), *act.Attributes.Email)
				}
				break
			}
		}
		assert.True(rest.T(), found, "identity %s not found", expID.String())
	}
}

func (rest *TestCollaboratorsREST) checkPrivateCollaborators(expectedUserIDs []uuid.UUID, actualUsers *app.UserList) {
	for i, id := range expectedUserIDs {
		require.NotNil(rest.T(), actualUsers.Data[i].ID)
		require.Equal(rest.T(), id.String(), *actualUsers.Data[i].ID)
		assert.True(rest.T(), *actualUsers.Data[i].Attributes.EmailPrivate)
		require.NotEmpty(rest.T(), *actualUsers.Data[i].Attributes.Email)
	}
}

func (rest *TestCollaboratorsREST) TestRemoveCollaboratorsOk() {
	space := rest.Graph.LoadSpace(rest.spaceID)

	svc, ctrl := rest.SecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity2.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity3.ID.String())

	addPayload := &app.AddManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: rest.testIdentity1.ID.String(), Type: idnType}, {ID: rest.testIdentity2.ID.String(), Type: idnType}, {ID: rest.testIdentity3.ID.String(), Type: idnType}}}
	test.AddManyCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, addPayload)

	_, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID, rest.testIdentity2.ID, rest.testIdentity3.ID}, actualUsers)

	test.RemoveCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, rest.testIdentity2.ID.String())

	updatedResource, err := rest.Application.SpaceResources().LoadBySpace(context.Background(), &rest.spaceID)
	require.NoError(rest.T(), err)
	require.True(rest.T(), space.Resource().UpdatedAt.Before(updatedResource.UpdatedAt))

	_, actualUsers = test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID, rest.testIdentity3.ID}, actualUsers)
}

func (rest *TestCollaboratorsREST) TestRemoveManyCollaboratorsOk() {
	space := rest.Graph.LoadSpace(rest.spaceID)

	svc, ctrl := rest.SecuredController()
	rest.policy.AddUserToPolicy(rest.testIdentity1.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity2.ID.String())
	rest.policy.AddUserToPolicy(rest.testIdentity3.ID.String())

	addPayload := &app.AddManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: rest.testIdentity1.ID.String(), Type: idnType}, {ID: rest.testIdentity2.ID.String(), Type: idnType}, {ID: rest.testIdentity3.ID.String(), Type: idnType}}}
	test.AddManyCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, addPayload)

	_, actualUsers := test.ListCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, nil, nil, nil, nil)
	rest.checkCollaborators([]uuid.UUID{rest.testIdentity1.ID, rest.testIdentity2.ID, rest.testIdentity3.ID}, actualUsers)
	payload := &app.RemoveManyCollaboratorsPayload{Data: []*app.UpdateUserID{{ID: rest.testIdentity2.ID.String(), Type: idnType}, {ID: rest.testIdentity3.ID.String(), Type: idnType}}}

	test.RemoveManyCollaboratorsOK(rest.T(), svc.Context, svc, ctrl, rest.spaceID, payload)

	updatedResource, err := rest.Application.SpaceResources().LoadBySpace(context.Background(), &rest.spaceID)
	require.NoError(rest.T(), err)
	require.True(rest.T(), space.Resource().UpdatedAt.Before(updatedResource.UpdatedAt))
}

func (rest *TestCollaboratorsREST) createSpace() uuid.UUID {
	return rest.createSpaceByIdentity(nil)
}

func (rest *TestCollaboratorsREST) createSpaceByIdentity(identity *account.Identity) uuid.UUID {
	// given
	svc, _ := rest.SecuredControllerForIdentity(identity)
	spaceCtrl := NewSpaceController(svc, rest.Application, rest.Configuration, &DummyResourceManager{})
	require.NotNil(rest.T(), spaceCtrl)

	id := uuid.NewV4()
	test.CreateSpaceOK(rest.T(), svc.Context, svc, spaceCtrl, id)
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
