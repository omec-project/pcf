// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

// The test this replaces was 5QI <= 4, which is not the 3GPP definition.
func TestIsStandardisedGbr5QI(t *testing.T) {
	gbr := []int32{1, 2, 3, 4, 65, 66, 67, 71, 72, 73, 74, 75, 76}
	delayCritical := []int32{82, 83, 84, 85, 86, 87, 88, 89, 90}
	nonGbr := []int32{5, 6, 7, 8, 9, 10, 69, 70, 79, 80}

	for _, v := range append(gbr, delayCritical...) {
		if !IsStandardisedGbr5QI(v) {
			t.Errorf("5QI %d is a GBR resource type in TS 23.501 table 5.7.4-1", v)
		}
	}
	for _, v := range nonGbr {
		if IsStandardisedGbr5QI(v) {
			t.Errorf("5QI %d is Non-GBR and must not be treated as guaranteed", v)
		}
	}
}

// Everything above 4 was mishandled before. These are the values the old test got wrong.
func TestGbr5QIsAboveFourAreRecognised(t *testing.T) {
	for _, v := range []int32{65, 66, 67, 71, 76, 82, 90} {
		if !IsStandardisedGbr5QI(v) {
			t.Errorf("5QI %d was mishandled by the previous 5QI <= 4 test and must now be recognised", v)
		}
	}
}

// The call site the helper exists for. 5QI 66 is a GBR resource type in TS 23.501 table 5.7.4-1
// but fails a 5QI <= 4 test, so before this change an AF's guaranteed rate for it was returned
// empty and left the aggregate budget untouched — unbudgeted rather than refused.
// Rates are in kbps and ConvertBitRateToKbps is base 2, so 1 Mbps is 1024.
func TestDecreaseRemainGBRBudgetsGbr5QIAboveFour(t *testing.T) {
	remainUl, remainDl := 4096.0, 8192.0
	policy := &UeSmPolicyData{RemainGbrUL: &remainUl, RemainGbrDL: &remainDl}

	req := models.NewRequestedQos(66)
	req.SetGbrUl("1 Mbps")
	req.SetGbrDl("2 Mbps")

	gbrDl, gbrUl, err := policy.DecreaseRemainGBR(req)
	if err != nil {
		t.Fatalf("DecreaseRemainGBR: %v", err)
	}
	if gbrUl != "1 Mbps" || gbrDl != "2 Mbps" {
		t.Errorf("returned GBR = (%q, %q), want (%q, %q)", gbrUl, gbrDl, "1 Mbps", "2 Mbps")
	}
	if remainUl != 3072 || remainDl != 6144 {
		t.Errorf("remaining budget = (%v, %v) kbps, want (3072, 6144)", remainUl, remainDl)
	}
}

// The other direction, so the helper cannot be widened into budgeting everything: a standardised
// Non-GBR 5QI carrying rates is still not a GBR flow.
func TestDecreaseRemainGBRLeavesNonGbr5QIUnbudgeted(t *testing.T) {
	remainUl, remainDl := 4096.0, 8192.0
	policy := &UeSmPolicyData{RemainGbrUL: &remainUl, RemainGbrDL: &remainDl}

	req := models.NewRequestedQos(9)
	req.SetGbrUl("1 Mbps")
	req.SetGbrDl("2 Mbps")

	gbrDl, gbrUl, err := policy.DecreaseRemainGBR(req)
	if err != nil {
		t.Fatalf("DecreaseRemainGBR: %v", err)
	}
	if gbrUl != "" || gbrDl != "" {
		t.Errorf("returned GBR = (%q, %q), want both empty for a Non-GBR 5QI", gbrUl, gbrDl)
	}
	if remainUl != 4096 || remainDl != 8192 {
		t.Errorf("remaining budget = (%v, %v) kbps, want it untouched at (4096, 8192)", remainUl, remainDl)
	}
}

// The other half of the budget, and the reason both directions had to move together.
// RemovePccRule credits the aggregate back through IncreaseRemainGBR. Had that gate kept
// reading 5QI <= 4 while DecreaseRemainGBR moved to the table, a 5QI of 66 would be debited
// on allocation and never credited on release, and the UE's aggregate would shrink by the
// guaranteed rate once per rule, permanently.
func TestRemovePccRuleRestoresBudgetForGbr5QIAboveFour(t *testing.T) {
	remainUl, remainDl := 4096.0, 8192.0
	policy := newPolicyHoldingGbrRule(66, "1 Mbps", "2 Mbps", &remainUl, &remainDl)

	// What DecreaseRemainGBR took for this rule.
	remainUl -= 1024
	remainDl -= 2048

	if err := policy.RemovePccRule("rule-1", nil); err != nil {
		t.Fatalf("RemovePccRule: %v", err)
	}
	if remainUl != 4096 || remainDl != 8192 {
		t.Errorf("remaining budget = (%v, %v) kbps, want it back at (4096, 8192)", remainUl, remainDl)
	}
}

// The mirror, so the credit cannot later be widened into giving back a rate that was never
// budgeted: a standardised Non-GBR 5QI is not debited by DecreaseRemainGBR, so releasing it
// must not credit the aggregate either.
func TestRemovePccRuleLeavesBudgetAloneForNonGbr5QI(t *testing.T) {
	remainUl, remainDl := 4096.0, 8192.0
	policy := newPolicyHoldingGbrRule(9, "1 Mbps", "2 Mbps", &remainUl, &remainDl)

	if err := policy.RemovePccRule("rule-1", nil); err != nil {
		t.Fatalf("RemovePccRule: %v", err)
	}
	if remainUl != 4096 || remainDl != 8192 {
		t.Errorf("remaining budget = (%v, %v) kbps, want it untouched at (4096, 8192)", remainUl, remainDl)
	}
}

// The invariant the two gates exist to keep, stated end to end: whatever a GBR flow takes from
// the aggregate on allocation it gives back on release. Asserted on a 5QI of 66 because that is
// the value the two gates used to disagree about.
func TestDecreaseThenRemoveLeavesAggregateUnchanged(t *testing.T) {
	remainUl, remainDl := 4096.0, 8192.0
	policy := newPolicyHoldingGbrRule(66, "1 Mbps", "2 Mbps", &remainUl, &remainDl)

	req := models.NewRequestedQos(66)
	req.SetGbrUl("1 Mbps")
	req.SetGbrDl("2 Mbps")
	if _, _, err := policy.DecreaseRemainGBR(req); err != nil {
		t.Fatalf("DecreaseRemainGBR: %v", err)
	}
	if remainUl == 4096 || remainDl == 8192 {
		t.Fatalf("budget was not debited, so the test cannot show it being credited back")
	}

	if err := policy.RemovePccRule("rule-1", nil); err != nil {
		t.Fatalf("RemovePccRule: %v", err)
	}
	if remainUl != 4096 || remainDl != 8192 {
		t.Errorf("aggregate = (%v, %v) kbps after allocate and release, want (4096, 8192)", remainUl, remainDl)
	}
}

// A policy holding one PCC rule whose QoS data carries the given 5QI and guaranteed rates,
// which is the state RemovePccRule reads to decide what to credit back.
func newPolicyHoldingGbrRule(var5qi int32, gbrUl, gbrDl string, remainUl, remainDl *float64) *UeSmPolicyData {
	qos := models.NewQosData("qos-1")
	qos.SetVar5qi(var5qi)
	qos.SetGbrUl(gbrUl)
	qos.SetGbrDl(gbrDl)

	rule := models.NewPccRule("rule-1")
	rule.SetRefQosData([]string{"qos-1"})

	decision := models.NewSmPolicyDecision()
	decision.SetPccRules(map[string]models.PccRule{"rule-1": *rule})
	decision.SetQosDecs(map[string]models.QosData{"qos-1": *qos})

	return &UeSmPolicyData{
		RemainGbrUL:            remainUl,
		RemainGbrDL:            remainDl,
		PolicyDecision:         decision,
		PackFiltMapToPccRuleId: map[string]string{},
	}
}
