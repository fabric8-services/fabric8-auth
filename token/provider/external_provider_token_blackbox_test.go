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

type externalTokenBlackboxTest struct {
	gormtestsupport.DBTestSuite
	repo  provider.ExternalTokenRepository
	clean func()
	ctx   context.Context
}

func TestRunExternalTokenBlackboxTest(t *testing.T) {
	suite.Run(t, &externalTokenBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite("")})
}

func (s *externalTokenBlackboxTest) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.ctx = migration.NewMigrationContext(context.Background())
	s.DBTestSuite.PopulateDBTestSuite(s.ctx)
}

func (s *externalTokenBlackboxTest) SetupTest() {
	s.repo = provider.NewExternalTokenRepository(s.DB)
	s.clean = cleaner.DeleteCreatedEntities(s.DB)
}

func (s *externalTokenBlackboxTest) TearDownTest() {
	s.clean()
}

func (s *externalTokenBlackboxTest) TestOKToDelete() {
	// given
	externalToken := createAndLoadExternalToken(s)

	err := s.repo.Delete(s.ctx, externalToken.ID)
	// then
	assert.Nil(s.T(), err)
	externalTokenLoaded, err := s.repo.Load(s.ctx, externalToken.ID)
	require.Nil(s.T(), externalTokenLoaded, "should have been deleted")
	require.IsType(s.T(), errors.NotFoundError{}, err)
}

func (s *externalTokenBlackboxTest) TestExternalProviderOKToLoad() {
	createAndLoadExternalToken(s)
}

func (s *externalTokenBlackboxTest) TestExistsExternalProvider() {
	t := s.T()
	resource.Require(t, resource.Database)

	t.Run("externalToken exists", func(t *testing.T) {
		//t.Parallel()
		// given
		externalToken := createAndLoadExternalToken(s)
		// when
		err := s.repo.CheckExists(s.ctx, externalToken.ID.String())
		// then
		require.Nil(t, err)
	})

	t.Run("externalToken doesn't exist", func(t *testing.T) {
		//t.Parallel()
		err := s.repo.CheckExists(s.ctx, uuid.NewV4().String())
		// then
		require.IsType(t, errors.NotFoundError{}, err)
	})

}

func (s *externalTokenBlackboxTest) TestExternalProviderOKToSave() {
	// given
	externalToken := createAndLoadExternalToken(s)
	// when
	externalToken.Token = uuid.NewV4().String()
	err := s.repo.Save(s.ctx, externalToken)
	// then
	require.Nil(s.T(), err, "Could not update externalToken")
	externalTokenLoaded, err := s.repo.Load(s.ctx, externalToken.ID)

	require.Nil(s.T(), err, "Could not retrieve externalToken")
	require.Equal(s.T(), externalToken.Token, externalTokenLoaded.Token)
}

func (s *externalTokenBlackboxTest) TestExternalProviderOKToFilterByIdentityID() {
	// given
	externalToken := createAndLoadExternalToken(s)
	// when
	tokens, err := s.repo.Query(provider.ExternalTokenFilterByIdentityID(externalToken.IdentityID))

	// then
	require.Nil(s.T(), err, "Could not filter out externalTokens")

	require.NotZero(s.T(), len(tokens))
	for _, t := range tokens {
		require.Equal(s.T(), externalToken.ID, t.ID)
		require.Equal(s.T(), externalToken.Token, t.Token)
		require.Equal(s.T(), externalToken.IdentityID, t.IdentityID)
	}

}

func (s *externalTokenBlackboxTest) TestExternalProviderOKToFilterByProviderID() {
	// given
	externalToken := createAndLoadExternalToken(s)
	// when
	tokens, err := s.repo.Query(provider.ExternalTokenFilterByProviderID(externalToken.ProviderID))

	// then
	require.Nil(s.T(), err, "Could not filter out externalTokens")
	for _, t := range tokens {
		require.Equal(s.T(), externalToken.ID, t.ID)
		require.Equal(s.T(), externalToken.Token, t.Token)
		require.Equal(s.T(), externalToken.IdentityID, t.IdentityID)
	}

}

func (s *externalTokenBlackboxTest) TestExternalProviderOKToFilterByIdentityIDAndProviderID() {
	// given
	externalToken := createAndLoadExternalToken(s)
	// when
	tokens, err := s.repo.LoadByProviderIDAndIdentityID(s.ctx, externalToken.ProviderID, externalToken.IdentityID)

	// then
	require.Nil(s.T(), err, "Could not filter out externalTokens")

	require.NotZero(s.T(), len(tokens))
	for _, t := range tokens {
		require.Equal(s.T(), externalToken.ID, t.ID)
		require.Equal(s.T(), externalToken.Token, t.Token)
		require.Equal(s.T(), externalToken.IdentityID, t.IdentityID)
	}

}

func createAndLoadExternalToken(s *externalTokenBlackboxTest) *provider.ExternalToken {

	identity, err := test.CreateTestIdentity(s.DB, uuid.NewV4().String(), "kc")
	require.Nil(s.T(), err)

	externalToken := provider.ExternalToken{
		ID:         uuid.NewV4(),
		ProviderID: uuid.NewV4(),
		Token:      uuid.NewV4().String(),
		Scope:      "user:full",
		IdentityID: identity.ID,
	}
	fmt.Println(externalToken)

	err = s.repo.Create(s.ctx, &externalToken)
	require.Nil(s.T(), err, "Could not create externalToken")
	// when
	externalTokenRetrieved, err := s.repo.Load(s.ctx, externalToken.ID)
	// then
	require.Nil(s.T(), err, "Could not load externalToken")
	require.Equal(s.T(), externalToken.ID, externalTokenRetrieved.ID)
	return externalTokenRetrieved
}
