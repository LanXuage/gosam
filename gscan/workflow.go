package gscan

import (
	"go.temporal.io/sdk/workflow"
)

func ScanWorkflow(ctx workflow.Context, targets string) (string, error) {
	logger := workflow.GetLogger(ctx)

	ao := workflow.ActivityOptions{}
	ctx = workflow.WithActivityOptions(ctx, ao)

	var a *Activities

	var scanResult string
	err := workflow.ExecuteActivity(ctx, a.GetGreeting).Get(ctx, &scanResult)
	if err != nil {
		logger.Error("Get greeting failed.", "Error", err)
		return "", err
	}
	// @@@SNIPEND

	// Get Name.
	var nameResult string
	err = workflow.ExecuteActivity(ctx, a.GetName).Get(ctx, &nameResult)
	if err != nil {
		logger.Error("Get name failed.", "Error", err)
		return "", err
	}

	// Say Greeting.
	var sayResult string
	err = workflow.ExecuteActivity(ctx, a.SayGreeting, scanResult, nameResult).Get(ctx, &sayResult)
	if err != nil {
		logger.Error("Marshalling failed with error.", "Error", err)
		return "", err
	}

	logger.Info("GreetingSample completed.", "Result", sayResult)
	return sayResult, nil
}
