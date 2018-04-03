package model_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	invitationRepo "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	//organizationModelService "github.com/fabric8-services/fabric8-auth/authorization/organization/model"
	//resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	//identityrole "github.com/fabric8-services/fabric8-auth/authorization/role/identityrole/repository"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"

	"github.com/stretchr/testify/suite"
)

type invitationModelServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	invitationRepo invitationRepo.InvitationRepository
	identityRepo   account.IdentityRepository
}

func TestRunInvitationModelServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &invitationModelServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *invitationModelServiceBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.identityRepo = account.NewIdentityRepository(s.DB)
}
