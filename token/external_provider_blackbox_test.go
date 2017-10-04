package token_test

import (
	"context"
	"testing"

	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport/cleaner"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/migration"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/token"

	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type externalProviderBlackboxTest struct {
	gormtestsupport.DBTestSuite
	repo  token.ExternalProviderRepository
	clean func()
	ctx   context.Context
}

func TestRunExternalProviderBlackboxTest(t *testing.T) {
	suite.Run(t, &externalProviderBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite("../config.yaml")})
}

func (s *externalProviderBlackboxTest) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.ctx = migration.NewMigrationContext(context.Background())
	s.DBTestSuite.PopulateDBTestSuite(s.ctx)
}

func (s *externalProviderBlackboxTest) SetupTest() {
	s.repo = token.NewExternalProviderRepository(s.DB)
	s.clean = cleaner.DeleteCreatedEntities(s.DB)
}

func (s *externalProviderBlackboxTest) TearDownTest() {
	s.clean()
}

func (s *externalProviderBlackboxTest) TestOKToDelete() {
	// given
	externalProvider := token.ExternalProvider{
		ID:   uuid.NewV4(),
		Type: "openshift-v3",
		URL:  "https://console.oso.com",
	}

	err := s.repo.Create(s.ctx, &externalProvider)
	require.Nil(s.T(), err, "Could not create externalProvider")

	err = s.repo.Delete(s.ctx, externalProvider.ID)
	// then
	assert.Nil(s.T(), err)
	externalProviderLoaded, err := s.repo.Load(s.ctx, externalProvider.ID)
	require.Nil(s.T(), externalProviderLoaded, "should have been deleted")
	require.NotNil(s.T(), err)
}

func (s *externalProviderBlackboxTest) TestExternalProviderOKToLoad() {
	createAndLoadExternalProvider(s)
}

func (s *externalProviderBlackboxTest) TestExistsExternalProvider() {
	t := s.T()
	resource.Require(t, resource.Database)

	t.Run("externalProvider exists", func(t *testing.T) {
		//t.Parallel()
		// given
		externalProvider := createAndLoadExternalProvider(s)
		// when
		err := s.repo.CheckExists(s.ctx, externalProvider.ID.String())
		// then
		require.Nil(t, err)
	})

	t.Run("externalProvider doesn't exist", func(t *testing.T) {
		//t.Parallel()
		err := s.repo.CheckExists(s.ctx, uuid.NewV4().String())
		// then
		require.IsType(t, errors.NotFoundError{}, err)
	})

}

func (s *externalProviderBlackboxTest) TestExternalProviderOKToSave() {
	// given
	externalProvider := createAndLoadExternalProvider(s)
	// when
	externalProvider.URL = "https://console.oso.com" + uuid.NewV4().String()
	err := s.repo.Save(s.ctx, externalProvider)
	// then
	require.Nil(s.T(), err, "Could not update externalProvider")
}

func createAndLoadExternalProvider(s *externalProviderBlackboxTest) *token.ExternalProvider {
	externalProvider := token.ExternalProvider{
		ID:   uuid.NewV4(),
		Type: "openshift-v3",
		URL:  "https://console.oso.com",
	}
	err := s.repo.Create(s.ctx, &externalProvider)
	require.Nil(s.T(), err, "Could not create externalProvider")
	// when
	externalProviderRetrieved, err := s.repo.Load(s.ctx, externalProvider.ID)
	// then
	require.Nil(s.T(), err, "Could not load externalProvider")
	require.Equal(s.T(), externalProvider.ID, externalProviderRetrieved.ID)
	return externalProviderRetrieved
}
