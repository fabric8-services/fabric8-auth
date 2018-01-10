package resource_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"

	"github.com/stretchr/testify/suite"
)

type resourceTypeScopeBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo             resource.ResourceTypeScopeRepository
	resourceTypeRepo resource.ResourceTypeRepository
}

func TestRunResourceTypeScopeBlackBoxTest(t *testing.T) {
	suite.Run(t, &resourceTypeScopeBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *resourceTypeScopeBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.DB.LogMode(true)
	s.repo = resource.NewResourceTypeScopeRepository(s.DB)
	s.resourceTypeRepo = resource.NewResourceTypeRepository(s.DB)
}
