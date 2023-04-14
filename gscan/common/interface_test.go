package common_test

import (
	"gscan/common"
	"testing"
)

func TestGetActiveInterfaces(t *testing.T) {
	t.Log(common.GetActiveInterfaces())
}
