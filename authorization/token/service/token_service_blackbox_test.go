package service_test

import (
		"testing"
		"github.com/fabric8-services/fabric8-auth/gormtestsupport"
		"github.com/stretchr/testify/suite"
)

type  tokenServiceBlackboxTest struct {
	gormtestsupport.DBTestSuite
}

func TestRunTokenServiceBlackboxTest(t *testing.T) {
	suite.Run(t, &tokenServiceBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *tokenServiceBlackboxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
}
