// Copyright (C) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2025 Canonical Ltd.
// SPDX-License-Identifier: Apache-2.0

package polling

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/nfConfigApi"
	"github.com/omec-project/pcf/consumer"
	"github.com/omec-project/pcf/util"
)

const applicationJson = "application/json"

const (
	testDnn1    = "dnn1"
	testDnn2    = "dnn2"
	testRuleId1 = "id1"
)

func newArp() *models.Arp {
	arp := models.NewArpWithDefaults()
	arp.SetPriorityLevel(0)
	return arp
}

// The polling loop, fetching, backoff and dedupe are tested in openapi/nfconfigpoll. The tests below
// check the PCF wiring (endpoint, config type, delivery) and the PCF specific handling of a polled
// policy control config.

func startPoller(t *testing.T, handler http.HandlerFunc) <-chan consumer.NfProfileDynamicConfig {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	ch := make(chan consumer.NfProfileDynamicConfig, 4)
	poller, err := newPoller(srv.URL, ch, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); poller.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return ch
}

func TestPolling_DeliversNfProfileConfig(t *testing.T) {
	originalPccPolicies := pccPolicies
	pccPolicies = make(map[SnssaiKey]*PccPolicy)
	t.Cleanup(func() { pccPolicies = originalPccPolicies })
	body, err := json.Marshal([]nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 1},
			Dnns:     []string{testDnn1},
			PccRules: []nfConfigApi.PccRule{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ch := startPoller(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != pollingPath {
			t.Errorf("polled %s, want %s", r.URL.Path, pollingPath)
		}
		w.Header().Set("Content-Type", applicationJson)
		if _, err := w.Write(body); err != nil {
			t.Errorf("write response: %v", err)
		}
	})

	expectedNfProfile := consumer.NfProfileDynamicConfig{
		Plmns: map[models.PlmnId]struct{}{{Mcc: "001", Mnc: "01"}: {}},
		Dnns:  map[string]struct{}{testDnn1: {}},
	}
	select {
	case result := <-ch:
		if !reflect.DeepEqual(result, expectedNfProfile) {
			t.Errorf("Expected %+v, got %+v", expectedNfProfile, result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no NF profile config delivered")
	}
	select {
	case got := <-ch:
		t.Errorf("unchanged config delivered again: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestPolling_EmptyInitialConfigIsNotDelivered(t *testing.T) {
	var polls atomic.Int32
	ch := startPoller(t, func(w http.ResponseWriter, r *http.Request) {
		polls.Add(1)
		w.Header().Set("Content-Type", applicationJson)
		if _, err := w.Write([]byte(`[]`)); err != nil {
			t.Errorf("write response: %v", err)
		}
	})

	deadline := time.Now().Add(2 * time.Second)
	for polls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if polls.Load() < 3 {
		t.Fatal("poller did not poll")
	}
	select {
	case got := <-ch:
		t.Errorf("empty config delivered before any policy control was configured: %+v", got)
	default:
	}
}

func TestHandlePolledPolicyControl_DeliveryFailureIsRetriedAndNothingIsRecorded(t *testing.T) {
	originalPccPolicies := pccPolicies
	pccPolicies = make(map[SnssaiKey]*PccPolicy)
	t.Cleanup(func() { pccPolicies = originalPccPolicies })

	input := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 1},
			PccRules: []nfConfigApi.PccRule{{RuleId: testRuleId1}},
		},
	}
	// unbuffered channel without a reader and an already cancelled context: delivery fails
	poller := nfConfigPoller{
		currentPolicyControl: []nfConfigApi.PolicyControl{},
		nfProfileConfigChan:  make(chan consumer.NfProfileDynamicConfig),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := poller.handlePolledPolicyControl(ctx, input); err == nil {
		t.Fatal("expected an error when the NF profile config cannot be delivered")
	}
	if len(poller.currentNfProfileConfig.Plmns) != 0 || len(poller.currentPolicyControl) != 0 {
		t.Errorf("state recorded despite failed delivery: %+v, %+v", poller.currentNfProfileConfig, poller.currentPolicyControl)
	}
	if len(pccPolicies) != 0 {
		t.Errorf("pcc policies updated despite failed delivery: %+v", pccPolicies)
	}
}

func TestHandlePolledPolicyControl_ExpectChannelNotToBeUpdated(t *testing.T) {
	pc1 := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 1},
			PccRules: []nfConfigApi.PccRule{},
		},
	}
	newSnssaiPc := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 5},
			PccRules: []nfConfigApi.PccRule{},
		},
	}
	nfProf := consumer.NfProfileDynamicConfig{
		Plmns: map[models.PlmnId]struct{}{{Mcc: "001", Mnc: "01"}: {}},
		Dnns:  map[string]struct{}{},
	}

	tests := []struct {
		name                   string
		initialPolicyControl   []nfConfigApi.PolicyControl
		initialNfProfileConfig consumer.NfProfileDynamicConfig
		input                  []nfConfigApi.PolicyControl
	}{
		{
			name:                   "Same policy control, nf registration is not updated",
			initialPolicyControl:   pc1,
			initialNfProfileConfig: nfProf,
			input:                  pc1,
		},
		{
			name:                   "New config has different snssai",
			initialPolicyControl:   pc1,
			initialNfProfileConfig: nfProf,
			input:                  newSnssaiPc,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			originalPccPolicies := pccPolicies
			pccPolicies = make(map[SnssaiKey]*PccPolicy)
			defer func() {
				pccPolicies = originalPccPolicies
			}()

			pollingChan := make(chan consumer.NfProfileDynamicConfig, 1)
			poller := nfConfigPoller{
				currentPolicyControl:   tc.initialPolicyControl,
				currentNfProfileConfig: tc.initialNfProfileConfig,
				nfProfileConfigChan:    pollingChan,
			}

			if err := poller.handlePolledPolicyControl(context.Background(), tc.input); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			select {
			case updated := <-pollingChan:
				t.Errorf("Unexpected channel send: %+v", updated)
			case <-time.After(100 * time.Millisecond):
				// Expected
			}

			if !reflect.DeepEqual(poller.currentNfProfileConfig, tc.initialNfProfileConfig) {
				t.Errorf("Expected current Nf Profile config: %+v, got: %+v",
					tc.initialNfProfileConfig, poller.currentNfProfileConfig)
			}

			if !reflect.DeepEqual(poller.currentPolicyControl, tc.input) {
				t.Errorf("Expected current policy control config: %+v, got: %+v",
					tc.input, poller.currentPolicyControl)
			}
		})
	}
}

func TestHandlePolledPolicyControl_ExpectNFRegistrationChannelUpdate(t *testing.T) {
	pc1 := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 1},
			Dnns:     []string{testDnn1},
			PccRules: []nfConfigApi.PccRule{},
		},
	}
	newPlmnPc := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "002", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 5},
			Dnns:     []string{testDnn1},
			PccRules: []nfConfigApi.PccRule{},
		},
	}
	newDnnPc := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 1},
			Dnns:     []string{testDnn2},
			PccRules: []nfConfigApi.PccRule{},
		},
	}
	nfProf1 := consumer.NfProfileDynamicConfig{
		Plmns: map[models.PlmnId]struct{}{{Mcc: "001", Mnc: "01"}: {}},
		Dnns:  map[string]struct{}{testDnn1: {}},
	}

	newPlmnNfProfile := consumer.NfProfileDynamicConfig{
		Plmns: map[models.PlmnId]struct{}{{Mcc: "002", Mnc: "01"}: {}},
		Dnns:  map[string]struct{}{testDnn1: {}},
	}
	newDnnNfProfile := consumer.NfProfileDynamicConfig{
		Plmns: map[models.PlmnId]struct{}{{Mcc: "001", Mnc: "01"}: {}},
		Dnns:  map[string]struct{}{testDnn2: {}},
	}

	tests := []struct {
		name                   string
		initialPolicyControl   []nfConfigApi.PolicyControl
		initialNfProfileConfig consumer.NfProfileDynamicConfig
		input                  []nfConfigApi.PolicyControl
		expectedPolicyControl  []nfConfigApi.PolicyControl
		expectedNfProfile      consumer.NfProfileDynamicConfig
	}{
		{
			name:                   "Previous config is empty, new config is not empty",
			initialPolicyControl:   []nfConfigApi.PolicyControl{},
			initialNfProfileConfig: consumer.NfProfileDynamicConfig{},
			input:                  pc1,
			expectedPolicyControl:  pc1,
			expectedNfProfile:      nfProf1,
		},
		{
			name:                   "Plmn config changed",
			initialPolicyControl:   pc1,
			initialNfProfileConfig: nfProf1,
			input:                  newPlmnPc,
			expectedPolicyControl:  newPlmnPc,
			expectedNfProfile:      newPlmnNfProfile,
		},
		{
			name:                   "DNN config changed",
			initialPolicyControl:   pc1,
			initialNfProfileConfig: nfProf1,
			input:                  newDnnPc,
			expectedPolicyControl:  newDnnPc,
			expectedNfProfile:      newDnnNfProfile,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			originalPccPolicies := pccPolicies
			pccPolicies = make(map[SnssaiKey]*PccPolicy)
			defer func() {
				pccPolicies = originalPccPolicies
			}()

			pollingChan := make(chan consumer.NfProfileDynamicConfig, 1)
			poller := nfConfigPoller{
				currentPolicyControl:   tc.initialPolicyControl,
				currentNfProfileConfig: tc.initialNfProfileConfig,
				nfProfileConfigChan:    pollingChan,
			}

			if err := poller.handlePolledPolicyControl(context.Background(), tc.input); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			select {
			case updated := <-pollingChan:
				if !reflect.DeepEqual(updated, tc.expectedNfProfile) {
					t.Errorf("Wrong config sent on channel.\nExpected: %+v\nGot: %+v", tc.expectedNfProfile, updated)
				}
			case <-time.After(100 * time.Millisecond):
				t.Error("Expected update to be sent to channel but none received")
			}

			if !reflect.DeepEqual(poller.currentNfProfileConfig, tc.expectedNfProfile) {
				t.Errorf("Expected current Nf Profile config: %+v, got: %+v",
					tc.expectedNfProfile, poller.currentNfProfileConfig)
			}

			if !reflect.DeepEqual(poller.currentPolicyControl, tc.expectedPolicyControl) {
				t.Errorf("Expected current policy control config: %+v, got: %+v",
					tc.expectedPolicyControl, poller.currentPolicyControl)
			}
		})
	}
}

func TestHandlePolledPolicyControl_ExpectPccConfigNotToBeUpdated(t *testing.T) {
	pc1 := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 1},
			Dnns:     []string{testDnn1},
			PccRules: []nfConfigApi.PccRule{},
		},
	}
	newPlmnPc := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "02"},
			Snssai:   nfConfigApi.Snssai{Sst: 1},
			Dnns:     []string{testDnn1},
			PccRules: []nfConfigApi.PccRule{},
		},
	}

	newDnnPc := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 1},
			Dnns:     []string{testDnn2},
			PccRules: []nfConfigApi.PccRule{},
		},
	}

	tests := []struct {
		name                 string
		initialPolicyControl []nfConfigApi.PolicyControl
		input                []nfConfigApi.PolicyControl
	}{
		{
			name:                 "Same policy control, nf registration is not updated",
			initialPolicyControl: pc1,
			input:                pc1,
		},
		{
			name:                 "Initial config is empty, new config empty",
			initialPolicyControl: []nfConfigApi.PolicyControl{},
			input:                []nfConfigApi.PolicyControl{},
		},
		{
			name:                 "New config has different plmn",
			initialPolicyControl: pc1,
			input:                newPlmnPc,
		},
		{
			name:                 "New config has different dnns",
			initialPolicyControl: pc1,
			input:                newDnnPc,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			originalPccPolicies := pccPolicies
			defer func() {
				pccPolicies = originalPccPolicies
			}()

			initialPccPolicies := map[SnssaiKey]*PccPolicy{
				{Sst: 1}: {PccRules: map[string]*models.PccRule{
					testRuleId1: {},
				}},
			}
			pccPolicies = map[SnssaiKey]*PccPolicy{
				{Sst: 1}: {PccRules: map[string]*models.PccRule{
					testRuleId1: {},
				}},
			}

			pollingChan := make(chan consumer.NfProfileDynamicConfig, 1)
			poller := nfConfigPoller{
				currentPolicyControl: tc.initialPolicyControl,
				nfProfileConfigChan:  pollingChan,
			}

			if err := poller.handlePolledPolicyControl(context.Background(), tc.input); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(poller.currentPolicyControl, tc.input) {
				t.Errorf("expected current policy control config: %+v, got: %+v",
					tc.input, poller.currentPolicyControl)
			}
			if !reflect.DeepEqual(pccPolicies, initialPccPolicies) {
				t.Errorf("expected pcc policies: %+v, got: %+v",
					initialPccPolicies, pccPolicies)
			}
		})
	}
}

func TestHandlePolledPolicyControl_ExpectPccConfigToBeUpdated(t *testing.T) {
	originalPccPolicies := pccPolicies
	defer func() {
		pccPolicies = originalPccPolicies
	}()
	pc1 := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 1},
			Dnns:     []string{testDnn1},
			PccRules: []nfConfigApi.PccRule{{RuleId: testRuleId1}},
		},
	}
	newSnssaiPc := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 2},
			Dnns:     []string{testDnn1},
			PccRules: []nfConfigApi.PccRule{{RuleId: testRuleId1}},
		},
	}

	newPccRules := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 1},
			Dnns:     []string{testDnn1},
			PccRules: []nfConfigApi.PccRule{{RuleId: "id2"}},
		},
	}

	tests := []struct {
		name                 string
		initialPolicyControl []nfConfigApi.PolicyControl
		initialPccPolicies   map[SnssaiKey]*PccPolicy
		input                []nfConfigApi.PolicyControl
		expectedPccPolicies  map[SnssaiKey]*PccPolicy
	}{
		{
			name:                 "New config has different snssai",
			initialPolicyControl: pc1,
			initialPccPolicies: map[SnssaiKey]*PccPolicy{
				{Sst: 1}: {PccRules: map[string]*models.PccRule{
					testRuleId1: {},
				}},
			},
			input: newSnssaiPc,
			expectedPccPolicies: map[SnssaiKey]*PccPolicy{
				{Sst: 2}: {
					PccRules: map[string]*models.PccRule{
						testRuleId1: {
							PccRuleId:  "1",
							RefQosData: []string{"1"},
							FlowInfos:  make([]models.FlowInformation, 0),
							RefTcData:  make([]string, 0),
						},
					},
					TraffContDecs: make(map[string]*models.TrafficControlData),
					QosDecs: map[string]*models.QosData{
						"1": {
							QosId: "1",
							Arp:   newArp(),
						},
					},
				},
			},
		},
		{
			name:                 "New config has different pcc Rules",
			initialPolicyControl: pc1,
			initialPccPolicies: map[SnssaiKey]*PccPolicy{
				{Sst: 1}: {PccRules: map[string]*models.PccRule{
					testRuleId1: {},
				}},
			},
			input: newPccRules,
			expectedPccPolicies: map[SnssaiKey]*PccPolicy{
				{Sst: 1}: {
					PccRules: map[string]*models.PccRule{
						"id2": {
							PccRuleId:  "1",
							RefQosData: []string{"1"},
							FlowInfos:  make([]models.FlowInformation, 0),
							RefTcData:  make([]string, 0),
						},
					},
					TraffContDecs: make(map[string]*models.TrafficControlData),
					QosDecs: map[string]*models.QosData{
						"1": {
							QosId: "1",
							Arp:   newArp(),
						},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pccPolicies = tc.initialPccPolicies
			pollingChan := make(chan consumer.NfProfileDynamicConfig, 1)
			poller := nfConfigPoller{
				currentPolicyControl: tc.initialPolicyControl,
				nfProfileConfigChan:  pollingChan,
			}

			if err := poller.handlePolledPolicyControl(context.Background(), tc.input); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(poller.currentPolicyControl, tc.input) {
				t.Errorf("expected current policy control config: %+v, got: %+v",
					tc.input, poller.currentPolicyControl)
			}
			if !util.CompareViaJSON(tc.expectedPccPolicies, pccPolicies) {
				t.Errorf("PccPolicy mismatch")
				expectedJSON, err := json.MarshalIndent(pccPoliciesForDebug(tc.expectedPccPolicies), "", "  ")
				if err != nil {
					t.Logf("Failed to marshal expected PccPolicy: %v", err)
				} else {
					t.Logf("Expected PccPolicy: %s", expectedJSON)
				}
				actualJSON, err := json.MarshalIndent(pccPoliciesForDebug(pccPolicies), "", "  ")
				if err != nil {
					t.Logf("Failed to marshal actual PccPolicy: %v", err)
				} else {
					t.Logf("Actual PccPolicy: %s", actualJSON)
				}
			}
		})
	}
}
