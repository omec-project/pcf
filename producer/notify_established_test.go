// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"errors"
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/polling"
)

func decisionWithArp(levels ...int32) *models.SmPolicyDecision {
	qosDecs := map[string]models.QosData{}
	for i, level := range levels {
		qosDecs[string(rune('a'+i))] = models.QosData{
			Arp: &models.Arp{PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(level))},
		}
	}
	d := &models.SmPolicyDecision{}
	d.SetQosDecs(qosDecs)
	return d
}

// TS 23.501 clause 5.7.2.2: the ARP priority range is 1 to 15 with 1 as the highest. Sorting the
// wrong way would pace the least important sites first, which is the opposite of what an operator
// re-prioritising during an incident is asking for.
func TestArpPriorityTakesTheMostImportantFlow(t *testing.T) {
	tests := []struct {
		name     string
		decision *models.SmPolicyDecision
		want     int32
	}{
		{"single flow", decisionWithArp(5), 5},
		{"most important of several", decisionWithArp(9, 2, 14), 2},
		{"highest possible", decisionWithArp(1, 15), 1},
		{"no ARP anywhere sorts last", decisionWithArp(), 16},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := defaultQosArpPriority(tc.decision); got != tc.want {
				t.Errorf("arp priority = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestPacedFanOutIsOrderedHighestPriorityFirst(t *testing.T) {
	pending := []pendingNotification{
		{smPolicyID: "low", arpPriority: 12},
		{smPolicyID: "highest", arpPriority: 1},
		{smPolicyID: "middle", arpPriority: 6},
		{smPolicyID: "none", arpPriority: 16},
	}

	sortByPriority(pending)

	want := []string{"highest", "middle", "low", "none"}
	for i, id := range want {
		if pending[i].smPolicyID != id {
			t.Fatalf("position %d = %q, want %q — ARP 1 is the highest priority, so ascending",
				i, pending[i].smPolicyID, id)
		}
	}
}

// Sessions at equal priority keep their relative order, so a slice-wide change does not reshuffle
// subscribers arbitrarily between one poll and the next.
func TestEqualPrioritiesKeepTheirOrder(t *testing.T) {
	pending := []pendingNotification{
		{smPolicyID: "first", arpPriority: 5},
		{smPolicyID: "second", arpPriority: 5},
		{smPolicyID: "third", arpPriority: 5},
	}

	sortByPriority(pending)

	for i, id := range []string{"first", "second", "third"} {
		if pending[i].smPolicyID != id {
			t.Errorf("position %d = %q, want %q", i, pending[i].smPolicyID, id)
		}
	}
}

// establishedSession puts one session in the UE pool with the decision it was given at
// establishment, so a recompute has something to compare against.
func establishedSession(t *testing.T, sessionAmbr *models.Ambr, given *models.SmPolicyDecision) *pcfContext.UeSmPolicyData {
	t.Helper()

	// No per-IMSI session rules configured, which is the ordinary case and the branch that builds
	// the session rule from the subscribed AMBR.
	originalRules := polling.GetImsiSessionRules
	polling.GetImsiSessionRules = func(string, string) (map[string]*models.SessionRule, error) {
		return nil, errors.New("no imsi session rules configured")
	}
	t.Cleanup(func() { polling.GetImsiSessionRules = originalRules })

	supi := "imsi-208930100007487"
	smPolicyID := supi + "-10"
	sst := int32(1)
	sd := "010203"

	ue := &pcfContext.UeContext{Supi: supi, SmPolicyData: map[string]*pcfContext.UeSmPolicyData{}}
	ctx := &models.SmPolicyContextData{
		Supi:            supi,
		PduSessionId:    10,
		Dnn:             "internet",
		SliceInfo:       models.Snssai{Sst: sst, Sd: openapi.PtrString(sd)},
		NotificationUri: "http://smf:29502/nsmf-callback",
		SubsSessAmbr:    sessionAmbr,
		// The SMF always supplies this at policy-create, and the recompute reads back the same
		// stored context — so a session that established successfully always has one here.
		SubsDefQos: &models.SubscribedDefaultQos{Var5qi: 9, Arp: models.Arp{
			PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(8)),
		}},
	}
	smPolicy := &pcfContext.UeSmPolicyData{PolicyContext: ctx, PolicyDecision: given}
	ue.SmPolicyData[smPolicyID] = smPolicy
	pcfContext.PCF_Self().UePool.Store(supi, ue)

	t.Cleanup(func() { pcfContext.PCF_Self().UePool.Delete(supi) })
	return smPolicy
}

// A slice policy edit must reach a session that is already running, rather than waiting for the
// subscriber to re-establish.
func TestPolicyRuleChangeReachesAnEstablishedSession(t *testing.T) {
	original := getSlicePccPolicy
	t.Cleanup(func() { getSlicePccPolicy = original })

	getSlicePccPolicy = func(models.Snssai) *polling.PccPolicy {
		return &polling.PccPolicy{
			PccRules: map[string]*models.PccRule{"rule1": {PccRuleId: "rule1", Precedence: openapi.PtrInt32(200)}},
			QosDecs:  map[string]*models.QosData{"qos1": {QosId: "qos1", Var5qi: openapi.PtrInt32(10)}},
		}
	}

	// The session was given an empty decision, so anything the new policy produces is a change.
	smPolicy := establishedSession(t, nil, &models.SmPolicyDecision{})

	pending := recomputeChangedSessions()

	if len(pending) != 1 {
		t.Fatalf("pending notifications = %d, want the established session to be told", len(pending))
	}
	if smPolicy.PolicyDecision == nil || len(smPolicy.PolicyDecision.GetPccRules()) == 0 {
		t.Error("the session's stored decision must be updated to the new policy")
	}
}

// A change that leaves a session's decision alone must signal nothing. The cost of a needless
// notification is a radio reconfiguration, not this element's work.
func TestUnchangedDecisionSignalsNothing(t *testing.T) {
	original := getSlicePccPolicy
	t.Cleanup(func() { getSlicePccPolicy = original })

	getSlicePccPolicy = func(models.Snssai) *polling.PccPolicy {
		return &polling.PccPolicy{
			PccRules: map[string]*models.PccRule{"rule1": {PccRuleId: "rule1"}},
			QosDecs:  map[string]*models.QosData{"qos1": {QosId: "qos1"}},
		}
	}

	// Establish, then recompute twice: the second pass has nothing to do.
	establishedSession(t, nil, &models.SmPolicyDecision{})
	if first := recomputeChangedSessions(); len(first) != 1 {
		t.Fatalf("first recompute = %d, want the initial difference to be seen", len(first))
	}

	second := recomputeChangedSessions()

	if len(second) != 0 {
		t.Errorf("second recompute = %d, want nothing: the policy did not change between them", len(second))
	}
}

// Session-AMBR cannot be changed mid-session, and this pins why rather than leaving it to a
// reading of the code. It reaches the PCF from the SMF at policy-create time, sourced from
// subscription data, and is not part of the polled configuration — so a recompute reads back the
// value the session already had, whatever the slice policy now says.
func TestSessionAmbrIsNotChangedByAPolicyEdit(t *testing.T) {
	original := getSlicePccPolicy
	t.Cleanup(func() { getSlicePccPolicy = original })

	getSlicePccPolicy = func(models.Snssai) *polling.PccPolicy {
		return &polling.PccPolicy{
			PccRules: map[string]*models.PccRule{"rule1": {PccRuleId: "rule1"}},
			QosDecs:  map[string]*models.QosData{"qos1": {QosId: "qos1"}},
		}
	}

	subscribed := &models.Ambr{Uplink: "50 Mbps", Downlink: "50 Mbps"}
	smPolicy := establishedSession(t, subscribed, &models.SmPolicyDecision{})

	recomputeChangedSessions()

	for _, rule := range smPolicy.PolicyDecision.GetSessRules() {
		ambr := rule.GetAuthSessAmbr()
		if ambr.Uplink != "50 Mbps" || ambr.Downlink != "50 Mbps" {
			t.Errorf("session AMBR = %s/%s, want the subscribed value: a policy edit cannot change it",
				ambr.Uplink, ambr.Downlink)
		}
	}
}
