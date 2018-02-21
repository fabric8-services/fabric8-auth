package repository_test

import (
	"testing"

	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	//"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type resourceTypeBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo resourcetype.ResourceTypeRepository
}

var knownResourceTypes = [2]string{"openshift.io/resource/area", "identity/organization"}

func TestRunResourceTypeBlackBoxTest(t *testing.T) {
	suite.Run(t, &resourceTypeBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *resourceTypeBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = resourcetype.NewResourceTypeRepository(s.DB)
}

func (s *resourceTypeBlackBoxTest) TestDefaultResourceTypesExist() {
	t := s.T()

	t.Run("resource type exists", func(t *testing.T) {

		for _, resourceType := range knownResourceTypes {
			_, err := s.repo.Lookup(s.Ctx, resourceType)
			// then
			require.Nil(t, err)
		}

		// Check that only these resource types exist
		var types, errs = s.repo.List(s.Ctx)
		require.Nil(t, errs)

		require.EqualValues(t, len(knownResourceTypes), len(types))
	})
}
