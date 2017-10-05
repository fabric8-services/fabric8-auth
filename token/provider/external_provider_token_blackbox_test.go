package provider_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport/cleaner"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/migration"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/test"
	"github.com/fabric8-services/fabric8-auth/token/provider"

	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type externalProviderTokenBlackboxTest struct {
	gormtestsupport.DBTestSuite
	repo  provider.ExternalProviderTokenRepository
	clean func()
	ctx   context.Context
}

func TestRunExternalProviderTokenBlackboxTest(t *testing.T) {
	suite.Run(t, &externalProviderTokenBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite("")})
}

func (s *externalProviderTokenBlackboxTest) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.ctx = migration.NewMigrationContext(context.Background())
	s.DBTestSuite.PopulateDBTestSuite(s.ctx)
}

func (s *externalProviderTokenBlackboxTest) SetupTest() {
	s.repo = provider.NewExternalProviderTokenRepository(s.DB)
	s.clean = cleaner.DeleteCreatedEntities(s.DB)
}

func (s *externalProviderTokenBlackboxTest) TearDownTest() {
	s.clean()
}

func (s *externalProviderTokenBlackboxTest) TestOKToDelete() {
	// given
	externalProviderToken := createAndLoadExternalProviderToken(s)

	err := s.repo.Delete(s.ctx, externalProviderToken.ID)
	// then
	assert.Nil(s.T(), err)
	externalProviderTokenLoaded, err := s.repo.Load(s.ctx, externalProviderToken.ID)
	require.Nil(s.T(), externalProviderTokenLoaded, "should have been deleted")
	require.IsType(s.T(), errors.NotFoundError{}, err)
}

func (s *externalProviderTokenBlackboxTest) TestExternalProviderOKToLoad() {
	createAndLoadExternalProviderToken(s)
}

func (s *externalProviderTokenBlackboxTest) TestExistsExternalProvider() {
	t := s.T()
	resource.Require(t, resource.Database)

	t.Run("externalProviderToken exists", func(t *testing.T) {
		//t.Parallel()
		// given
		externalProviderToken := createAndLoadExternalProviderToken(s)
		// when
		err := s.repo.CheckExists(s.ctx, externalProviderToken.ID.String())
		// then
		require.Nil(t, err)
	})

	t.Run("externalProviderToken doesn't exist", func(t *testing.T) {
		//t.Parallel()
		err := s.repo.CheckExists(s.ctx, uuid.NewV4().String())
		// then
		require.IsType(t, errors.NotFoundError{}, err)
	})

}

func (s *externalProviderTokenBlackboxTest) TestExternalProviderOKToSave() {
	// given
	externalProvideToken := createAndLoadExternalProviderToken(s)
	// when
	externalProvideToken.Token = uuid.NewV4().String()
	err := s.repo.Save(s.ctx, externalProvideToken)
	// then
	require.Nil(s.T(), err, "Could not update externalProvideToken")
	externalProviderTokenLoaded, err := s.repo.Load(s.ctx, externalProvideToken.ID)

	require.Nil(s.T(), err, "Could not retrieve externalProviderToken")
	require.Equal(s.T(), externalProvideToken.Token, externalProviderTokenLoaded.Token)
}

func (s *externalProviderTokenBlackboxTest) TestExternalProviderOKToFilterByIdentityID() {
	// given
	externalProvideToken := createAndLoadExternalProviderToken(s)
	// when
	tokens, err := s.repo.Query(provider.ExternalProviderTokenFilterByIdentityID(externalProvideToken.IdentityID))

	// then
	require.Nil(s.T(), err, "Could not filter out externalProviderTokens")

	require.NotZero(s.T(), len(tokens))
	for _, t := range tokens {
		require.Equal(s.T(), externalProvideToken.ID, t.ID)
		require.Equal(s.T(), externalProvideToken.Token, t.Token)
		require.Equal(s.T(), externalProvideToken.IdentityID, t.IdentityID)
	}

}

func (s *externalProviderTokenBlackboxTest) TestExternalProviderOKToFilterByProviderID() {
	// given
	externalProvideToken := createAndLoadExternalProviderToken(s)
	// when
	tokens, err := s.repo.Query(provider.ExternalProviderTokenFilterByProviderID(externalProvideToken.ProviderID))

	// then
	require.Nil(s.T(), err, "Could not filter out externalProviderTokens")
	for _, t := range tokens {
		require.Equal(s.T(), externalProvideToken.ID, t.ID)
		require.Equal(s.T(), externalProvideToken.Token, t.Token)
		require.Equal(s.T(), externalProvideToken.IdentityID, t.IdentityID)
	}

}

func (s *externalProviderTokenBlackboxTest) TestExternalProviderOKToFilterByIdentityIDAndProviderID() {
	// given
	externalProvideToken := createAndLoadExternalProviderToken(s)
	// when
	tokens, err := s.repo.LoadByProviderIDAndIdentityID(s.ctx, externalProvideToken.ProviderID, externalProvideToken.IdentityID)

	// then
	require.Nil(s.T(), err, "Could not filter out externalProviderTokens")

	require.NotZero(s.T(), len(tokens))
	for _, t := range tokens {
		require.Equal(s.T(), externalProvideToken.ID, t.ID)
		require.Equal(s.T(), externalProvideToken.Token, t.Token)
		require.Equal(s.T(), externalProvideToken.IdentityID, t.IdentityID)
	}

}

func createAndLoadExternalProviderToken(s *externalProviderTokenBlackboxTest) *provider.ExternalProviderToken {

	identity, err := test.CreateTestIdentity(s.DB, uuid.NewV4().String(), "kc")
	require.Nil(s.T(), err)

	externalProviderToken := provider.ExternalProviderToken{
		ID:         uuid.NewV4(),
		ProviderID: uuid.NewV4(),
		Token:      uuid.NewV4().String(),
		Scope:      "user:full",
		IdentityID: identity.ID,
	}
	fmt.Println(externalProviderToken)

	err = s.repo.Create(s.ctx, &externalProviderToken)
	require.Nil(s.T(), err, "Could not create externalProviderToken")
	// when
	externalProviderTokenRetrieved, err := s.repo.Load(s.ctx, externalProviderToken.ID)
	// then
	require.Nil(s.T(), err, "Could not load externalProviderToken")
	require.Equal(s.T(), externalProviderToken.ID, externalProviderTokenRetrieved.ID)
	return externalProviderTokenRetrieved
}
