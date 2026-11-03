// Copyright (C) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package policyauthorization

import "testing"

func TestDecodeUpdateData(t *testing.T) {
	const comps = `"medComponents":{"0":{"medCompN":1,"qosReference":"qosVoNR"}}`
	tests := []struct {
		name, body string
		wantComps  int
		wantErr    bool
	}{
		{"wrapped (TS 29.514 AppSessionContextUpdateDataPatch)", `{"ascReqData":{` + comps + `}}`, 1, false},
		{"bare (legacy)", `{` + comps + `}`, 1, false},
		{"wrapped, null ascReqData", `{"ascReqData":null}`, 0, false},
		{"wrapped, empty", `{"ascReqData":{}}`, 0, false},
		{"empty body", ``, 0, false},
		{"not json", `{`, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeUpdateData([]byte(tc.body))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if n := len(got.GetMedComponents()); n != tc.wantComps {
				t.Errorf("got %d media components, want %d", n, tc.wantComps)
			}
			if comp, ok := got.GetMedComponents()["0"]; tc.wantComps == 1 && (!ok || comp.GetQosReference() != "qosVoNR") {
				t.Errorf("qosReference lost: %+v", comp)
			}
		})
	}
}
