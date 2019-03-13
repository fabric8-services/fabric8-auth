package controller_test

import (
	"context"
	"reflect"
	"strconv"
	"testing"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/application/transaction"
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestRunSearchUser(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &TestSearchUserSearch{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

type TestSearchUserSearch struct {
	gormtestsupport.DBTestSuite
	svc        *goa.Service
	controller *SearchController
}

func (s *TestSearchUserSearch) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.svc, s.controller = s.SecuredController()
}

type userSearchTestArgs struct {
	pageOffset *string
	pageLimit  *int
	q          string
}

type userSearchTestExpect func(*testing.T, okScenarioUserSearchTest, *app.UserList)
type userSearchTestExpects []userSearchTestExpect

type okScenarioUserSearchTest struct {
	name                  string
	userSearchTestArgs    userSearchTestArgs
	userSearchTestExpects userSearchTestExpects
}

func (s *TestSearchUserSearch) TestUsersSearchOK() {

	idents := s.createTestData()
	defer s.cleanTestData(idents)

	tests := []okScenarioUserSearchTest{
		{"With sanitized params", userSearchTestArgs{s.offset(0), s.limit(10), "x_test'"}, userSearchTestExpects{s.totalCount(0)}},
		{"Without A-Z ,a-z or 0-9", userSearchTestArgs{s.offset(0), s.limit(10), "."}, userSearchTestExpects{s.totalCount(0)}},
		{"Without A-Z ,a-z or 0-9", userSearchTestArgs{s.offset(0), s.limit(10), ".@"}, userSearchTestExpects{s.totalCount(0)}},
		{"Without A-Z ,a-z or 0-9", userSearchTestArgs{s.offset(0), s.limit(10), "a@"}, userSearchTestExpects{s.totalCountAtLeast(0)}},
		{"Too short", userSearchTestArgs{s.offset(0), s.limit(10), "x"}, userSearchTestExpects{s.totalCountAtLeast(0)}},
		{"Two characters are OK", userSearchTestArgs{s.offset(0), s.limit(10), "x_"}, userSearchTestExpects{s.totalCountAtLeast(0)}},
		{"With lowercase fullname query", userSearchTestArgs{s.offset(0), s.limit(10), "x_test_ab"}, userSearchTestExpects{s.totalCountAtLeast(2)}},
		{"With uppercase fullname query", userSearchTestArgs{s.offset(0), s.limit(10), "X_TEST_AB"}, userSearchTestExpects{s.totalCountAtLeast(2)}},
		{"With uppercase email query", userSearchTestArgs{s.offset(0), s.limit(10), "EMAIL_X_TEST_AB"}, userSearchTestExpects{s.totalCountAtLeast(1)}},
		{"With lowercase email query", userSearchTestArgs{s.offset(0), s.limit(10), "email_x_test_ab"}, userSearchTestExpects{s.totalCountAtLeast(1)}},
		{"With username query", userSearchTestArgs{s.offset(0), s.limit(10), "x_test_c"}, userSearchTestExpects{s.totalCountAtLeast(2)}},
		{"with special chars", userSearchTestArgs{s.offset(0), s.limit(10), "a'\"&:\n!#%?*"}, userSearchTestExpects{s.totalCount(0)}},
		{"with multi page", userSearchTestArgs{s.offset(0), s.limit(10), "TEST"}, userSearchTestExpects{s.hasLinks("Next")}},
		{"with last page", userSearchTestArgs{s.offset(len(idents) - 1), s.limit(10), "TEST"}, userSearchTestExpects{s.hasNoLinks("Next"), s.hasLinks("Prev")}},
		{"with different values", userSearchTestArgs{s.offset(0), s.limit(10), "TEST"}, userSearchTestExpects{s.differentValues(s.createDifferentTestData())}},
		{"With offset exceeded the max limit total count", userSearchTestArgs{s.offset(s.Configuration.GetMaxUsersListLimit() + 1), s.limit(1), "TEST_"}, userSearchTestExpects{s.totalCount(s.Configuration.GetMaxUsersListLimit())}},
		{"With offset exceeded the max limit result size", userSearchTestArgs{s.offset(s.Configuration.GetMaxUsersListLimit() + 1), s.limit(1), "TEST_"}, userSearchTestExpects{s.resultLen(0)}},
		{"With offset + limit exceeded the max limit total count", userSearchTestArgs{s.offset(0), s.limit(s.Configuration.GetMaxUsersListLimit() + 1), "TEST_"}, userSearchTestExpects{s.totalCount(s.Configuration.GetMaxUsersListLimit())}},
		{"With offset + limit exceeded the max limit result size", userSearchTestArgs{s.offset(0), s.limit(s.Configuration.GetMaxUsersListLimit() + 1), "TEST_"}, userSearchTestExpects{s.resultLen(s.Configuration.GetMaxUsersListLimit())}},
		{"Within the max limit total count", userSearchTestArgs{s.offset(10), s.limit(5), "TEST_"}, userSearchTestExpects{s.totalCount(s.Configuration.GetMaxUsersListLimit())}},
		{"Within the max limit result size", userSearchTestArgs{s.offset(10), s.limit(5), "TEST_"}, userSearchTestExpects{s.resultLen(5)}},
	}

	for _, tt := range tests {
		_, result := test.UsersSearchOK(s.T(), s.controller.Context, s.svc, s.controller, tt.userSearchTestArgs.pageLimit, tt.userSearchTestArgs.pageOffset, tt.userSearchTestArgs.q)
		for _, userSearchTestExpect := range tt.userSearchTestExpects {
			userSearchTestExpect(s.T(), tt, result)
		}
	}
}

func (s *TestSearchUserSearch) TestUsersSearchBadRequest() {

	t := s.T()
	tests := []struct {
		name               string
		userSearchTestArgs userSearchTestArgs
	}{
		{"with empty query", userSearchTestArgs{s.offset(0), s.limit(10), ""}},
	}

	for _, tt := range tests {
		test.UsersSearchBadRequest(t, s.controller.Context, s.svc, s.controller, tt.userSearchTestArgs.pageLimit, tt.userSearchTestArgs.pageOffset, tt.userSearchTestArgs.q)
	}
}

func (s *TestSearchUserSearch) createTestData() []account.Identity {
	names := []string{"X_TEST_A", "X_TEST_AB", "X_TEST_B", "X_TEST_C"}
	emails := []string{"email_x_test_ab@redhat.org", "email_x_test_a@redhat.org", "email_x_test_c@redhat.org", "email_x_test_b@redhat.org"}
	usernames := []string{"x_test_b", "x_test_c", "x_test_a", "x_test_ab"}
	for i := 0; i < s.Configuration.GetMaxUsersListLimit(); i++ {
		names = append(names, "TEST_"+strconv.Itoa(i))
		emails = append(emails, "myemail"+strconv.Itoa(i))
		usernames = append(usernames, "myusernames"+strconv.Itoa(i))
	}

	idents := []account.Identity{}

	err := transaction.Transactional(s.Application, func(tr transaction.TransactionalResources) error {
		for i, name := range names {

			user := account.User{
				FullName: name,
				ImageURL: "http://example.org/" + name + ".png",
				Email:    emails[i],
				Cluster:  "default Cluster",
			}
			err := tr.Users().Create(context.Background(), &user)
			require.Nil(s.T(), err)

			ident := account.Identity{
				User:         user,
				Username:     usernames[i] + uuid.NewV4().String(),
				ProviderType: "kc",
			}
			err = tr.Identities().Create(context.Background(), &ident)
			require.Nil(s.T(), err)

			idents = append(idents, ident)
		}
		return nil
	})
	require.Nil(s.T(), err)
	return idents
}

func (s *TestSearchUserSearch) createDifferentTestData() account.Identity {
	user := &account.User{
		Email:   uuid.NewV4().String(),
		Cluster: "test cluster",
		ID:      uuid.NewV4(),
	}
	result, err := testsupport.CreateTestUser(s.DB, user)
	require.NoError(s.T(), err)
	return result
}

func (s *TestSearchUserSearch) TestEmailPrivateSearchOK() {

	randomName := uuid.NewV4().String()
	email := uuid.NewV4().String()
	user := account.User{
		EmailPrivate: true,
		FullName:     randomName,
		ImageURL:     "http://example.org/" + randomName + ".png",
		Email:        email,
		Cluster:      "default Cluster",
	}

	_, err := testsupport.CreateTestUser(s.DB, &user)
	require.Nil(s.T(), err)

	offset := "0"
	pageLimit := 1
	// OK to search by username
	_, results := test.UsersSearchOK(s.T(), s.controller.Context, s.svc, s.controller, &pageLimit, &offset, randomName)

	for _, result := range results.Data {
		require.Equal(s.T(), "", *result.Attributes.Email)
	}

	// Empty result if searching by private email
	_, results = test.UsersSearchOK(s.T(), s.controller.Context, s.svc, s.controller, &pageLimit, &offset, email)
	require.Empty(s.T(), results.Data)
}

func (s *TestSearchUserSearch) TestEmailNotPrivateSearchOK() {

	randomName := uuid.NewV4().String()
	user := account.User{
		EmailPrivate: false,
		FullName:     randomName,
		ImageURL:     "http://example.org/" + randomName + ".png",
		Email:        uuid.NewV4().String(),
		Cluster:      "default Cluster",
	}
	_, err := testsupport.CreateTestUser(s.DB, &user)
	require.Nil(s.T(), err)

	offset := "0"
	pageLimit := 1
	_, results := test.UsersSearchOK(s.T(), s.controller.Context, s.svc, s.controller, &pageLimit, &offset, randomName)

	for _, result := range results.Data {
		require.NotEmpty(s.T(), *result.Attributes.Email)
	}
}

func (s *TestSearchUserSearch) cleanTestData(idents []account.Identity) {
	err := transaction.Transactional(s.Application, func(tr transaction.TransactionalResources) error {
		db := tr.(*gormapplication.GormTransaction).DB()
		db = db.Unscoped()
		for _, ident := range idents {
			db.Delete(ident)
			db.Delete(&account.User{}, "id = ?", ident.User.ID)
		}
		return nil
	})
	require.Nil(s.T(), err)
}

func (s *TestSearchUserSearch) totalCount(count int) userSearchTestExpect {
	return func(t *testing.T, scenario okScenarioUserSearchTest, result *app.UserList) {
		if got := result.Meta.TotalCount; got != count {
			t.Errorf("%s got = %v, want %v", scenario.name, got, count)
		}
	}
}

func (s *TestSearchUserSearch) totalCountAtLeast(count int) userSearchTestExpect {
	return func(t *testing.T, scenario okScenarioUserSearchTest, result *app.UserList) {
		got := result.Meta.TotalCount
		if !(got >= count) {
			t.Errorf("%s got %v, wanted at least %v", scenario.name, got, count)
		}
	}
}

func (s *TestSearchUserSearch) resultLen(length int) userSearchTestExpect {
	return func(t *testing.T, scenario okScenarioUserSearchTest, result *app.UserList) {
		if length != len(result.Data) {
			t.Errorf("%s got %v, wanted %v", scenario.name, len(result.Data), length)
		}
	}
}

func (s *TestSearchUserSearch) hasLinks(linkNames ...string) userSearchTestExpect {
	return func(t *testing.T, scenario okScenarioUserSearchTest, result *app.UserList) {
		for _, linkName := range linkNames {
			link := linkName
			if reflect.Indirect(reflect.ValueOf(result.Links)).FieldByName(link).IsNil() {
				t.Errorf("%s got empty link, wanted %s", scenario.name, link)
			}
		}
	}
}

func (s *TestSearchUserSearch) hasNoLinks(linkNames ...string) userSearchTestExpect {
	return func(t *testing.T, scenario okScenarioUserSearchTest, result *app.UserList) {
		for _, linkName := range linkNames {
			if !reflect.Indirect(reflect.ValueOf(result.Links)).FieldByName(linkName).IsNil() {
				t.Errorf("%s got link, wanted empty %s", scenario.name, linkName)
			}
		}
	}
}

func (s *TestSearchUserSearch) differentValues(identity account.Identity) userSearchTestExpect {
	return func(t *testing.T, scenario okScenarioUserSearchTest, result *app.UserList) {
		for _, u := range result.Data {
			if identity.ID.String() == *u.ID {
				t.Errorf("%s got equal ID, wanted different %s", scenario.name, *u.ID)
			}
		}
	}
}

func (s *TestSearchUserSearch) limit(n int) *int {
	return &n
}

func (s *TestSearchUserSearch) offset(n int) *string {
	str := strconv.Itoa(n)
	return &str
}

func (s *TestSearchUserSearch) UnSecuredController() (*goa.Service, *SearchController) {
	svc := testsupport.UnsecuredService("Search-Service")
	ctrl := NewSearchController(svc, s.Application, s.Configuration)
	return svc, ctrl
}

func (s *TestSearchUserSearch) UnsecuredControllerBannedUser() (*goa.Service, *SearchController) {
	identity, err := testsupport.CreateBannedTestIdentityAndUser(s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)
	svc := testsupport.ServiceAsUser("Search-Service", identity)
	ctrl := NewSearchController(svc, s.Application, s.Configuration)
	return svc, ctrl
}

func (s *TestSearchUserSearch) SecuredController() (*goa.Service, *SearchController) {
	identity, err := testsupport.CreateTestIdentityAndUser(s.DB, uuid.NewV4().String(), "KC")
	require.NoError(s.T(), err)
	svc := testsupport.ServiceAsUser("Search-Service", identity)
	ctrl := NewSearchController(svc, s.Application, s.Configuration)
	return svc, ctrl
}

func (s *TestSearchUserSearch) TestSearchUnauthorized() {
	_, ctrl := s.UnSecuredController()
	test.UsersSearchUnauthorized(s.T(), ctrl.Context, ctrl.Service, ctrl, nil, nil, "a")
}

func (s *TestSearchUserSearch) TestSearchUnauthorizedForBannedUser() {
	_, ctrl := s.UnsecuredControllerBannedUser()
	test.UsersSearchUnauthorized(s.T(), ctrl.Context, ctrl.Service, ctrl, nil, nil, "a")
}
