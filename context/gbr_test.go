// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"sync"
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
)

// The test this replaces was 5QI <= 4, which is not the 3GPP definition.

// testQosID is the QoS data id the fixtures here hold their one rule under.
const testQosID = "qos-1"

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

	// What DecreaseRemainGBR took for this rule, recorded the way its callers do -- the credit is
	// the mirror of the recorded debit, not a reading of the rates the stored QoS data carries.
	remainUl -= 1024
	remainDl -= 2048
	policy.RecordGbrDebit(testQosID, "1 Mbps", "2 Mbps")

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
	gbrDl, gbrUl, err := policy.DecreaseRemainGBR(req)
	if err != nil {
		t.Fatalf("DecreaseRemainGBR: %v", err)
	}
	if remainUl == 4096 || remainDl == 8192 {
		t.Fatalf("budget was not debited, so the test cannot show it being credited back")
	}
	policy.RecordGbrDebit(testQosID, gbrUl, gbrDl)

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
	qos := models.NewQosData(testQosID)
	qos.SetVar5qi(var5qi)
	qos.SetGbrUl(gbrUl)
	qos.SetGbrDl(gbrDl)

	rule := models.NewPccRule("rule-1")
	rule.SetRefQosData([]string{testQosID})

	decision := models.NewSmPolicyDecision()
	decision.SetPccRules(map[string]models.PccRule{"rule-1": *rule})
	decision.SetQosDecs(map[string]models.QosData{testQosID: *qos})

	return &UeSmPolicyData{
		RemainGbrUL:            remainUl,
		RemainGbrDL:            remainDl,
		PolicyDecision:         decision,
		PackFiltMapToPccRuleId: map[string]string{},
	}
}

// The asymmetry that carrying guaranteed rates on slice-derived QoS data creates, and the reason
// the credit is taken from a recorded debit rather than from the stored rates.
//
// A rule the slice policy supplied has guaranteed rates on its QoS data but never went through
// DecreaseRemainGBR -- only an application function's request does. It still reaches RemovePccRule
// by the ordinary routes: a delete operation, or an installation the SMF reports as failed. Reading
// the stored rates there would hand back a rate nobody took and lift the aggregate above the budget
// the session started with.
func TestRemovePccRuleCreditsNothingForARuleThatWasNeverDebited(t *testing.T) {
	remainUl, remainDl := 4096.0, 8192.0
	policy := newPolicyHoldingGbrRule(66, "1 Mbps", "2 Mbps", &remainUl, &remainDl)

	// No RecordGbrDebit: this is a slice-derived rule, so nothing was taken for it.
	if err := policy.RemovePccRule("rule-1", nil); err != nil {
		t.Fatalf("RemovePccRule: %v", err)
	}
	if remainUl != 4096 || remainDl != 8192 {
		t.Errorf("aggregate = (%v, %v) kbps, want it untouched at (4096, 8192): nothing was debited for this rule",
			remainUl, remainDl)
	}
}

// The debit is both directions or neither. DecreaseRamainBitRate takes the downlink first, so a
// request whose uplink does not fit used to leave the downlink spent -- and the SM policy create
// arm returns on that error without restoring it, so the budget stayed short for the life of the
// session, once per refused request.
func TestDecreaseRemainGBRPutsTheDownlinkBackWhenTheUplinkDoesNotFit(t *testing.T) {
	remainUl, remainDl := 512.0, 8192.0
	policy := newPolicyHoldingGbrRule(66, "", "", &remainUl, &remainDl)

	req := models.NewRequestedQos(66)
	req.SetGbrUl("1 Mbps") // more than the 512 kbps left uplink
	req.SetGbrDl("2 Mbps") // fits, and is taken first
	gbrDl, _, err := policy.DecreaseRemainGBR(req)
	if err == nil {
		t.Fatal("expected the uplink debit to be refused")
	}
	if remainDl != 8192 {
		t.Errorf("downlink budget = %v kbps after a refused request, want it back at 8192", remainDl)
	}
	if gbrDl != "" {
		t.Errorf("gbrDl = %q, want it empty: nothing was granted", gbrDl)
	}
	if remainUl != 512 {
		t.Errorf("uplink budget = %v kbps, want it untouched at 512", remainUl)
	}
}

// The ledger is reached from two HTTP handlers for the same session -- the application function
// path records a debit while the SM policy update path releases a rule -- so it is shared state.
// Unguarded, a concurrent map write is a fatal runtime throw rather than a wrong number, which is
// a larger failure than the unsynchronised budget it mirrors. Run under -race.
func TestGbrLedgerSurvivesConcurrentRecordAndRelease(t *testing.T) {
	const iterations = 200
	remainUl, remainDl := 1<<20, 1<<20
	ul, dl := float64(remainUl), float64(remainDl)
	policy := newPolicyHoldingGbrRule(66, "1 Mbps", "2 Mbps", &ul, &dl)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			policy.RecordGbrDebit(testQosID, "1 Mbps", "2 Mbps")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			policy.IncreaseRemainGBR(testQosID)
		}
	}()
	wg.Wait()
}

// A modification that does not fit must leave the session exactly as it found it. The old call site
// credited the previous debit back, took the new one, and on failure restored the budget from a
// snapshot -- but the ledger entry had already been removed by the credit and was never put back,
// so the next release of that rule found nothing to give back and the aggregate shrank for good.
func TestReplaceGbrDebitRestoresTheLedgerWhenTheNewRequestDoesNotFit(t *testing.T) {
	remainUl, remainDl := 1024.0, 8192.0
	policy := newPolicyHoldingGbrRule(66, "1 Mbps", "2 Mbps", &remainUl, &remainDl)

	// The rule is already holding 1 Mbps up / 2 Mbps down of the aggregate.
	policy.RecordGbrDebit(testQosID, "1 Mbps", "2 Mbps")

	// Ask for more uplink than the session can carry even after the old debit is credited back.
	req := models.NewRequestedQos(66)
	req.SetGbrUl("100 Mbps")
	req.SetGbrDl("1 Mbps")
	if _, _, err := policy.ReplaceGbrDebit(testQosID, req); err == nil {
		t.Fatal("expected the replacement debit to be refused")
	}
	if remainUl != 1024 || remainDl != 8192 {
		t.Errorf("budget = (%v, %v) kbps after a refused modification, want it unchanged at (1024, 8192)",
			remainUl, remainDl)
	}

	// The proof the budget check alone cannot give: releasing the rule must still return the debit
	// that is once again in force.
	if err := policy.RemovePccRule("rule-1", nil); err != nil {
		t.Fatalf("RemovePccRule: %v", err)
	}
	if remainUl != 1024+1024 || remainDl != 8192+2048 {
		t.Errorf("budget = (%v, %v) kbps after releasing the rule, want the original debit credited back at (2048, 10240)",
			remainUl, remainDl)
	}
}

// The budget is rewritten through the pointers the session already holds, never replaced. Assigning
// a snapshot pointer installs nil whenever there was nothing to credit, and a nil budget reads
// downstream as no limit at all rather than as zero.
func TestReplaceGbrDebitKeepsTheSessionsBudgetPointers(t *testing.T) {
	remainUl, remainDl := 512.0, 512.0
	policy := newPolicyHoldingGbrRule(66, "", "", &remainUl, &remainDl)
	ulBefore, dlBefore := policy.RemainGbrUL, policy.RemainGbrDL

	// No prior debit recorded, so there is nothing to credit and the snapshots would be nil.
	req := models.NewRequestedQos(66)
	req.SetGbrUl("100 Mbps")
	req.SetGbrDl("100 Mbps")
	if _, _, err := policy.ReplaceGbrDebit(testQosID, req); err == nil {
		t.Fatal("expected the debit to be refused")
	}
	if policy.RemainGbrUL == nil || policy.RemainGbrDL == nil {
		t.Fatal("the budget pointers were replaced with nil, which reads downstream as no limit")
	}
	if policy.RemainGbrUL != ulBefore || policy.RemainGbrDL != dlBefore {
		t.Error("the budget pointers were swapped rather than rewritten")
	}
}

// The exchange has to be one transaction, not three locked steps. With the lock taken per map
// access, a release running between the credit and the record claims the id while no entry exists,
// and the debit written afterwards belongs to a rule that is already gone — so the aggregate stays
// short with nothing left to credit it back. Run under -race; the assertion is the invariant, not
// the race detector.
func TestReplaceGbrDebitIsOneTransactionAgainstAConcurrentRelease(t *testing.T) {
	const iterations = 300
	for i := 0; i < iterations; i++ {
		remainUl, remainDl := 100000.0, 100000.0
		policy := newPolicyHoldingGbrRule(66, "1 Mbps", "2 Mbps", &remainUl, &remainDl)
		policy.RecordGbrDebit(testQosID, "1 Mbps", "2 Mbps")

		req := models.NewRequestedQos(66)
		req.SetGbrUl("1 Mbps")
		req.SetGbrDl("2 Mbps")

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			// Either outcome is legitimate here; the invariant below is what is being tested.
			if _, _, err := policy.ReplaceGbrDebit(testQosID, req); err != nil {
				_ = err
			}
		}()
		go func() { defer wg.Done(); policy.IncreaseRemainGBR(testQosID) }()
		wg.Wait()

		// Whatever order they ran in, the ledger and the budget have to agree: an entry still
		// recorded means that much is still taken, and no entry means nothing is.
		//
		// The aggregate is the budget plus what is recorded against it, so the fixture's own
		// starting debit has to be added back to get the total this session began with -- the
		// first version of this test compared against the bare starting budget and failed for
		// its own arithmetic rather than for the code.
		debit, held := policy.takeGbrDebit(testQosID)
		wantUl, wantDl := 100000.0+1024, 100000.0+2048
		if held {
			ul, errUl := ConvertBitRateToKbps(debit.ul)
			dl, errDl := ConvertBitRateToKbps(debit.dl)
			if errUl != nil || errDl != nil {
				t.Fatalf("unparseable ledger entry %+v", debit)
			}
			wantUl -= ul
			wantDl -= dl
		}
		if remainUl != wantUl || remainDl != wantDl {
			t.Fatalf("iteration %d: budget (%v, %v) does not match the ledger (held=%v, %+v); want (%v, %v)",
				i, remainUl, remainDl, held, debit, wantUl, wantDl)
		}
	}
}

// The application-function debit and its ledger write are one transaction. They used to be two: the
// budget changed through the package-level helpers first, and the ledger was merged under the lock
// afterwards, so a release running in between claimed and credited the rule's entry and the merge
// then recorded a debit for a rule already removed. Asserted as the invariant -- the budget plus
// what the ledger still holds equals the aggregate -- after racing the two, under -race.
func TestDebitForAuthorizedQosIsOneTransactionAgainstAConcurrentRelease(t *testing.T) {
	const iterations = 300
	for i := 0; i < iterations; i++ {
		remainUl, remainDl := 100000.0, 100000.0
		policy := newPolicyHoldingGbrRule(66, "", "", &remainUl, &remainDl)

		qosData := models.QosData{QosId: testQosID}
		qosData.GbrUl = *openapi.NewNullableString(openapi.PtrString("1 Mbps"))
		qosData.GbrDl = *openapi.NewNullableString(openapi.PtrString("2 Mbps"))

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := policy.DebitForAuthorizedQos(&qosData, true, true); err != nil {
				t.Errorf("iteration %d: debit refused: %v", i, err)
			}
		}()
		go func() { defer wg.Done(); policy.IncreaseRemainGBR(testQosID) }()
		wg.Wait()

		debit, held := policy.takeGbrDebit(testQosID)
		wantUl, wantDl := 100000.0, 100000.0
		if held {
			ul, errUl := ConvertBitRateToKbps(debit.ul)
			dl, errDl := ConvertBitRateToKbps(debit.dl)
			if errUl != nil || errDl != nil {
				t.Fatalf("iteration %d: unparseable ledger entry %+v", i, debit)
			}
			wantUl -= ul
			wantDl -= dl
		}
		if remainUl != wantUl || remainDl != wantDl {
			t.Fatalf("iteration %d: budget (%v, %v) does not match the ledger (held=%v, %+v); want (%v, %v)",
				i, remainUl, remainDl, held, debit, wantUl, wantDl)
		}
	}
}

// A session with no aggregate GBR has nil budgets, which the debit treats as unlimited. Reading them
// for a log line must not dereference nil -- that panicked on exactly the requests just accepted.
func TestRemainingGbrKbpsRendersAnAbsentBudget(t *testing.T) {
	policy := &UeSmPolicyData{}
	ul, dl := policy.RemainingGbrKbps()
	if ul != "unlimited" || dl != "unlimited" {
		t.Errorf("RemainingGbrKbps() = (%q, %q), want (\"unlimited\", \"unlimited\")", ul, dl)
	}
	remain := 512.0
	policy.RemainGbrDL = &remain
	if _, dl := policy.RemainingGbrKbps(); dl != "512.00 Kbps" {
		t.Errorf("downlink = %q, want \"512.00 Kbps\"", dl)
	}
}
