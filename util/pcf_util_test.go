// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
)

type comparisonKey struct {
	Sst int32
	Sd  string
}

func TestCompareViaJSONWithTypedMapKeys(t *testing.T) {
	expected := map[comparisonKey]map[string]int{
		{Sst: 1, Sd: "010203"}: {"a": 1},
	}
	actual := map[comparisonKey]map[string]int{
		{Sst: 1, Sd: "010203"}: {"a": 1},
	}

	if !CompareViaJSON(expected, actual) {
		t.Fatal("expected CompareViaJSON to treat identical typed-key maps as equal")
	}
}

func TestCompareViaJSONDetectsTypedMapKeyDifferences(t *testing.T) {
	expected := map[comparisonKey]map[string]int{
		{Sst: 1, Sd: "010203"}: {"a": 1},
	}
	actual := map[comparisonKey]map[string]int{
		{Sst: 2, Sd: "010203"}: {"a": 1},
	}

	if CompareViaJSON(expected, actual) {
		t.Fatal("expected CompareViaJSON to detect different typed-key maps")
	}
}

// TestDeepCopyViaJSONPreservesNullableField checks that DeepCopyViaJSON preserves openapi
// Nullable* fields. Those types keep their state in unexported fields with only JSON
// marshalers, so reflection- or gob-based copying would silently drop them; the JSON
// round-trip honours their MarshalJSON/UnmarshalJSON.
func TestDeepCopyViaJSONPreservesNullableField(t *testing.T) {
	src := models.QosData{
		QosId:   "qos1",
		MaxbrUl: *openapi.NewNullableString(openapi.PtrString("100 Mbps")),
		Arp: &models.Arp{
			PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(5)),
			PreemptCap:    models.PREEMPTIONCAPABILITY_NOT_PREEMPT,
			PreemptVuln:   models.PREEMPTIONVULNERABILITY_NOT_PREEMPTABLE,
		},
	}

	var cp models.QosData
	if err := DeepCopyViaJSON(src, &cp); err != nil {
		t.Fatalf("DeepCopyViaJSON failed: %v", err)
	}

	if v := cp.MaxbrUl.Get(); v == nil || *v != "100 Mbps" {
		t.Errorf("MaxbrUl (NullableString) lost in copy: got %v, want \"100 Mbps\"", v)
	}
	if cp.Arp == nil {
		t.Fatal("Arp lost in copy")
	}
	if v := cp.Arp.PriorityLevel.Get(); v == nil || *v != 5 {
		t.Errorf("Arp.PriorityLevel (NullableInt32) lost in copy: got %v, want 5", v)
	}
}
