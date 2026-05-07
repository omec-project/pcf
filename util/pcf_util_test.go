// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package util

import "testing"

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
