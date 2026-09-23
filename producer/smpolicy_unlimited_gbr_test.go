// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	pcfContext "github.com/omec-project/pcf/context"
)

// A UE-initiated resource request for a guaranteed rate on a session with no aggregate GBR. The
// budget is nil there, which the debit treats as unlimited: it accepts the request and returns the
// rate. The log line that followed then dereferenced the nil budget, so the handler panicked on
// exactly the request it had just allowed. Driven through the procedure rather than the accessor,
// because what matters is that this call site no longer dereferences, not that a helper exists.
func TestResourceRequestOnASessionWithoutAggregateGbrDoesNotPanic(t *testing.T) {
	const supi = "imsi-001010123456790"
	smPolicyID := supi + "-10"

	self := pcfContext.PCF_Self()
	ue := &pcfContext.UeContext{
		Supi:         supi,
		SmPolicyData: make(map[string]*pcfContext.UeSmPolicyData),
	}
	self.UePool.Store(supi, ue)
	t.Cleanup(func() { self.UePool.Delete(supi) })

	policy := ue.NewUeSmPolicyData(smPolicyID, models.SmPolicyContextData{
		Supi:         supi,
		PduSessionId: 10,
		Dnn:          testDnn,
		SliceInfo:    testSnssai,
	}, &models.SmPolicyData{})
	if policy == nil {
		t.Fatal("failed to build the SM policy fixture")
	}
	policy.PolicyDecision = &models.SmPolicyDecision{}
	// No aggregate GBR on this session: both budgets stay nil.

	reqQos := models.NewRequestedQos(66)
	reqQos.SetGbrUl("1 Mbps")
	reqQos.SetGbrDl("2 Mbps")
	request := models.SmPolicyUpdateContextData{
		RepPolicyCtrlReqTriggers: []models.PolicyControlRequestTrigger{
			models.POLICYCONTROLREQUESTTRIGGER_RES_MO_RE,
		},
		UeInitResReq: &models.UeInitiatedResourceRequest{
			RuleOp:       models.RULEOPERATION_CREATE_PCC_RULE,
			ReqQos:       reqQos,
			PackFiltInfo: []models.PacketFilterInfo{{PackFiltCont: openapi.PtrString("permit out ip from any to any")}},
		},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the resource request panicked instead of being accepted: %v", r)
		}
	}()
	if _, problem := updateSmPolicyContextProcedure(request, smPolicyID); problem != nil {
		t.Fatalf("the resource request was refused: %+v", problem)
	}
}
