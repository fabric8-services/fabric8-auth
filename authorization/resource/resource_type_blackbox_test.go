package resource_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	//"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type resourceTypeBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo resource.ResourceTypeRepository
}

func TestRunResourceTypeBlackBoxTest(t *testing.T) {
	suite.Run(t, &resourceTypeBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *resourceTypeBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = resource.NewResourceTypeRepository(s.DB)
}

func (s *resourceTypeBlackBoxTest) TestDefaultResourceTypesExist() {
	t := s.T()

	t.Run("resource type exists", func(t *testing.T) {
		_, err := s.repo.Lookup(s.Ctx, "openshift.io/resource/area")
		// then
		require.Nil(t, err)

		// Check that only these resource types exist
		var types, errs = s.repo.List(s.Ctx)
		require.Nil(t, errs)

		require.EqualValues(t, 1, len(types))
	})
}
