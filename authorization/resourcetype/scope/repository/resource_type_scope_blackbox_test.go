package repository_test

import (
	"testing"

	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	scope "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/scope/repository"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"

	"github.com/stretchr/testify/suite"
)

type resourceTypeScopeBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo             scope.ResourceTypeScopeRepository
	resourceTypeRepo resourcetype.ResourceTypeRepository
}

func TestRunResourceTypeScopeBlackBoxTest(t *testing.T) {
	suite.Run(t, &resourceTypeScopeBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *resourceTypeScopeBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.DB.LogMode(true)
	s.repo = scope.NewResourceTypeScopeRepository(s.DB)
	s.resourceTypeRepo = resourcetype.NewResourceTypeRepository(s.DB)
}
