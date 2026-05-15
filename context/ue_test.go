// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

func TestIncreaseRemainGBR_IgnoresNilQosDecs(t *testing.T) {
	policy := &UeSmPolicyData{PolicyDecision: &models.SmPolicyDecision{}}

	origUL, origDL := policy.IncreaseRemainGBR("qos-1")
	if origUL != nil || origDL != nil {
		t.Fatalf("expected nil original GBR values, got %v and %v", origUL, origDL)
	}
}
