package gscan_test

import (
	"gscan"
	"testing"

	"github.com/stretchr/testify/suite"
	"go.temporal.io/sdk/testsuite"
)

type UnitTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite
}

func TestUnitTestSuite(t *testing.T) {
	suite.Run(t, new(UnitTestSuite))
}

func (s *UnitTestSuite) Test_SampleGreetingsWorkflow() {
	env := s.NewTestWorkflowEnvironment()
	var a *gscan.Activities
	//env.RegisterActivity(a)

	env.OnActivity(a.GetGreeting).Return("Hello", nil)
	env.OnActivity(a.GetName).Return("World", nil)
	env.OnActivity(a.SayGreeting, "Hello", "World").Return("Hello World!", nil)

	env.ExecuteWorkflow(gscan.ScanWorkflow)

	s.True(env.IsWorkflowCompleted())
	s.NoError(env.GetWorkflowError())

	env.AssertExpectations(s.T())
}
