package common_test

import (
	"gscan/common"
	"testing"
)

func TestGetGateways(t *testing.T) {
	a := common.GetInterfaces()
	t.Log(a)
}
