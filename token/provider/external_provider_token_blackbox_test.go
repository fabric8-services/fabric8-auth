package provider_test

import (
	"fmt"
	"testing"

	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/test"
	"github.com/fabric8-services/fabric8-auth/token/provider"

	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type externalTokenBlackboxTest struct {
	gormtestsupport.DBTestSuite
	repo *provider.GormExternalTokenRepository
}

func TestRunExternalTokenBlackboxTest(t *testing.T) {
	suite.Run(t, &externalTokenBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *externalTokenBlackboxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = provider.NewExternalTokenRepository(s.DB)
}

func (s *externalTokenBlackboxTest) TestOKToDelete() {
	// given
	externalToken := createAndLoadExternalToken(s)

	err := s.repo.Delete(s.Ctx, externalToken.ID)
	// then
	assert.Nil(s.T(), err)
	externalTokenLoaded, err := s.repo.Load(s.Ctx, externalToken.ID)
	require.Nil(s.T(), externalTokenLoaded, "should have been deleted")
	require.IsType(s.T(), errors.NotFoundError{}, err)
}

func (s *externalTokenBlackboxTest) TestTokenIsHardDeleted() {
	// create token
	externalToken := createAndLoadExternalToken(s)

	// check token exists
	var native provider.ExternalToken
	err := s.DB.Unscoped().Table(s.repo.TableName()).Where("id = ?", externalToken.ID).Find(&native).Error
	require.Nil(s.T(), err)

	// delete
	err = s.repo.Delete(s.Ctx, externalToken.ID)
	assert.Nil(s.T(), err)

	// load all records including soft deleted and check if the deleted record is among them
	err = s.DB.Unscoped().Table(s.repo.TableName()).Where("id = ?", externalToken.ID).Find(&native).Error
	require.NotNil(s.T(), err)
	require.Equal(s.T(), gorm.ErrRecordNotFound, err)
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
		err := s.repo.CheckExists(s.Ctx, externalToken.ID.String())
		// then
		require.Nil(t, err)
	})

	t.Run("externalToken doesn't exist", func(t *testing.T) {
		//t.Parallel()
		err := s.repo.CheckExists(s.Ctx, uuid.NewV4().String())
		// then
		require.IsType(t, errors.NotFoundError{}, err)
	})

}

func (s *externalTokenBlackboxTest) TestExternalProviderOKToSave() {
	// given
	externalToken := createAndLoadExternalToken(s)
	// when
	externalToken.Token = uuid.NewV4().String()
	err := s.repo.Save(s.Ctx, externalToken)
	// then
	require.Nil(s.T(), err, "Could not update externalToken")
	externalTokenLoaded, err := s.repo.Load(s.Ctx, externalToken.ID)

	require.Nil(s.T(), err, "Could not retrieve externalToken")
	s.assertToken(*externalToken, *externalTokenLoaded)
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
	tokens, err := s.repo.LoadByProviderIDAndIdentityID(s.Ctx, externalToken.ProviderID, externalToken.IdentityID)

	// then
	require.Nil(s.T(), err, "Could not filter out externalTokens")

	require.NotZero(s.T(), len(tokens))
	for _, t := range tokens {
		require.Equal(s.T(), externalToken.ID, t.ID)
		require.Equal(s.T(), externalToken.Token, t.Token)
		require.Equal(s.T(), externalToken.IdentityID, t.IdentityID)
	}

}

func (s *externalTokenBlackboxTest) TestExternalProviderOKToFilterByIdentityIDAndProviderIDLatest() {
	// given
	externalToken := createAndLoadExternalToken(s)

	lastTokenID := externalToken.ID // initialize
	for i := 0; i < 10; i++ {
		anotherExternalToken := provider.ExternalToken{
			ID:         uuid.NewV4(),
			ProviderID: externalToken.ProviderID,
			Token:      uuid.NewV4().String(),
			Scope:      "user:full",
			IdentityID: externalToken.IdentityID,
			Username:   externalToken.Username,
		}
		createExternalToken(s, anotherExternalToken)
		createAndLoadExternalToken(s) // add more noisy data

		lastTokenID = anotherExternalToken.ID
	}

	// when
	tokens, err := s.repo.LoadByProviderIDAndIdentityID(s.Ctx, externalToken.ProviderID, externalToken.IdentityID)

	// then
	require.Nil(s.T(), err, "Could not filter out externalTokens")

	require.Len(s.T(), tokens, 11)
	for _, t := range tokens {
		require.Equal(s.T(), externalToken.IdentityID, t.IdentityID)
		require.Equal(s.T(), externalToken.Username, t.Username)
	}

	require.Equal(s.T(), lastTokenID, tokens[0].ID)

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
		Username:   uuid.NewV4().String(),
	}
	fmt.Println(externalToken)

	err = s.repo.Create(s.Ctx, &externalToken)
	require.Nil(s.T(), err, "Could not create externalToken")
	// when
	externalTokenRetrieved, err := s.repo.Load(s.Ctx, externalToken.ID)
	// then
	require.Nil(s.T(), err, "Could not load externalToken")
	s.assertToken(externalToken, *externalTokenRetrieved)
	return externalTokenRetrieved
}

func createExternalToken(s *externalTokenBlackboxTest, externalToken provider.ExternalToken) *provider.ExternalToken {

	err := s.repo.Create(s.Ctx, &externalToken)
	require.Nil(s.T(), err, "Could not create externalToken")
	// when
	externalTokenRetrieved, err := s.repo.Load(s.Ctx, externalToken.ID)
	// then
	require.Nil(s.T(), err, "Could not load externalToken")
	s.assertToken(externalToken, *externalTokenRetrieved)
	return externalTokenRetrieved
}

func (s *externalTokenBlackboxTest) assertToken(expected provider.ExternalToken, actual provider.ExternalToken) {
	assert.Equal(s.T(), expected.ID, actual.ID)
	assert.Equal(s.T(), expected.IdentityID, actual.IdentityID)
	assert.Equal(s.T(), expected.ProviderID, actual.ProviderID)
	assert.Equal(s.T(), expected.Scope, actual.Scope)
	assert.Equal(s.T(), expected.Token, actual.Token)
	assert.Equal(s.T(), expected.Username, actual.Username)
}
