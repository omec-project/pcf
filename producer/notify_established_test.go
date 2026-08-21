// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
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
