// SPDX-FileCopyrightText: 2025 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
/*
 * NF Polling Unit Tests
 *
 */

package polling

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/openapi/nfConfigApi"
	"github.com/omec-project/pcf/consumer"
)

const applicationJson = "application/json"

func TestStartPollingService_Success(t *testing.T) {
	ctx := t.Context()
	originalFetchPolicyControlConfig := fetchPolicyControlConfig
	originalPccPolicies := pccPolicies
	defer func() {
		fetchPolicyControlConfig = originalFetchPolicyControlConfig
		pccPolicies = originalPccPolicies
	}()
	pccPolicies = make(map[models.Snssai]*PccPolicy)
	fetchedConfig := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 1},
			PccRules: []nfConfigApi.PccRule{{RuleId: "something"}},
		},
	}
	fetchPolicyControlConfig = func(p *nfConfigPoller, endpoint string) ([]nfConfigApi.PolicyControl, error) {
		return fetchedConfig, nil
	}

	expectedNfProfile := consumer.NfProfileDynamicConfig{
		Plmns: map[models.PlmnId]struct{}{{Mcc: "001", Mnc: "01"}: {}},
		Dnns:  map[string]struct{}{},
	}
	pollingChan := make(chan consumer.NfProfileDynamicConfig, 1)
	go StartPollingService(ctx, "http://dummy", pollingChan)
	time.Sleep(initialPollingInterval)

	select {
	case result := <-pollingChan:
		if !reflect.DeepEqual(result, expectedNfProfile) {
			t.Errorf("Expected %+v, got %+v", expectedNfProfile, result)
		}
	case <-time.After(100 * time.Millisecond):
		t.Errorf("Timeout waiting for PLMN config")
	}

	if len(pccPolicies) == 0 {
		t.Errorf("expected pccPolicies to be updated")
	}
}

func TestStartPollingService_RetryAfterFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	originalFetchPolicyControlConfig := fetchPolicyControlConfig
	originalPccPolicies := pccPolicies

	defer func() {
		fetchPolicyControlConfig = originalFetchPolicyControlConfig
		pccPolicies = originalPccPolicies
	}()

	callCount := 0
	fetchPolicyControlConfig = func(p *nfConfigPoller, endpoint string) ([]nfConfigApi.PolicyControl, error) {
		callCount++
		return nil, errors.New("mock failure")
	}
	pollingChan := make(chan consumer.NfProfileDynamicConfig, 1)
	go StartPollingService(ctx, "http://dummy", pollingChan)

	time.Sleep(4 * initialPollingInterval)
	cancel()
	<-ctx.Done()

	if callCount < 2 {
		t.Error("Expected to retry after failure")
	}
	t.Logf("Tried %v times", callCount)
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
			name:                   "Initial config is empty, new config empty",
			initialPolicyControl:   []nfConfigApi.PolicyControl{},
			initialNfProfileConfig: consumer.NfProfileDynamicConfig{},
			input:                  []nfConfigApi.PolicyControl{},
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
			originalFetchPolicyControlConfig := fetchPolicyControlConfig
			originalPccPolicies := pccPolicies
			pccPolicies = make(map[models.Snssai]*PccPolicy)
			defer func() {
				fetchPolicyControlConfig = originalFetchPolicyControlConfig
				pccPolicies = originalPccPolicies
			}()

			pollingChan := make(chan consumer.NfProfileDynamicConfig, 1)
			poller := nfConfigPoller{
				currentPolicyControl:   tc.initialPolicyControl,
				currentNfProfileConfig: tc.initialNfProfileConfig,
				nfProfileConfigChan:    pollingChan,
			}

			poller.handlePolledPolicyControl(tc.input)

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
			Dnns:     []string{"dnn1"},
			PccRules: []nfConfigApi.PccRule{},
		},
	}
	newPlmnPc := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "002", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 5},
			Dnns:     []string{"dnn1"},
			PccRules: []nfConfigApi.PccRule{},
		},
	}
	newDnnPc := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 1},
			Dnns:     []string{"dnn2"},
			PccRules: []nfConfigApi.PccRule{},
		},
	}
	nfProf1 := consumer.NfProfileDynamicConfig{
		Plmns: map[models.PlmnId]struct{}{{Mcc: "001", Mnc: "01"}: {}},
		Dnns:  map[string]struct{}{"dnn1": {}},
	}

	newPlmnNfProfile := consumer.NfProfileDynamicConfig{
		Plmns: map[models.PlmnId]struct{}{{Mcc: "002", Mnc: "01"}: {}},
		Dnns:  map[string]struct{}{"dnn1": {}},
	}
	newDnnNfProfile := consumer.NfProfileDynamicConfig{
		Plmns: map[models.PlmnId]struct{}{{Mcc: "001", Mnc: "01"}: {}},
		Dnns:  map[string]struct{}{"dnn2": {}},
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
			originalFetchPolicyControlConfig := fetchPolicyControlConfig
			originalPccPolicies := pccPolicies
			pccPolicies = make(map[models.Snssai]*PccPolicy)
			defer func() {
				fetchPolicyControlConfig = originalFetchPolicyControlConfig
				pccPolicies = originalPccPolicies
			}()

			pollingChan := make(chan consumer.NfProfileDynamicConfig, 1)
			poller := nfConfigPoller{
				currentPolicyControl:   tc.initialPolicyControl,
				currentNfProfileConfig: tc.initialNfProfileConfig,
				nfProfileConfigChan:    pollingChan,
			}

			poller.handlePolledPolicyControl(tc.input)

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
			Dnns:     []string{"dnn1"},
			PccRules: []nfConfigApi.PccRule{},
		},
	}
	newPlmnPc := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "02"},
			Snssai:   nfConfigApi.Snssai{Sst: 1},
			Dnns:     []string{"dnn1"},
			PccRules: []nfConfigApi.PccRule{},
		},
	}

	newDnnPc := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 1},
			Dnns:     []string{"dnn2"},
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
			originalFetchPolicyControlConfig := fetchPolicyControlConfig
			originalPccPolicies := pccPolicies
			defer func() {
				fetchPolicyControlConfig = originalFetchPolicyControlConfig
				pccPolicies = originalPccPolicies
			}()

			initialPccPolicies := map[models.Snssai]*PccPolicy{
				{Sst: 1}: {PccRules: map[string]*models.PccRule{
					"id1": {},
				}},
			}
			pccPolicies = map[models.Snssai]*PccPolicy{
				{Sst: 1}: {PccRules: map[string]*models.PccRule{
					"id1": {},
				}},
			}

			pollingChan := make(chan consumer.NfProfileDynamicConfig, 1)
			poller := nfConfigPoller{
				currentPolicyControl: tc.initialPolicyControl,
				nfProfileConfigChan:  pollingChan,
			}

			poller.handlePolledPolicyControl(tc.input)

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
	originalFetchPolicyControlConfig := fetchPolicyControlConfig
	originalPccPolicies := pccPolicies
	defer func() {
		fetchPolicyControlConfig = originalFetchPolicyControlConfig
		pccPolicies = originalPccPolicies
	}()
	pc1 := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 1},
			Dnns:     []string{"dnn1"},
			PccRules: []nfConfigApi.PccRule{{RuleId: "id1"}},
		},
	}
	newSnssaiPc := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 2},
			Dnns:     []string{"dnn1"},
			PccRules: []nfConfigApi.PccRule{{RuleId: "id1"}},
		},
	}

	newPccRules := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 1},
			Dnns:     []string{"dnn1"},
			PccRules: []nfConfigApi.PccRule{{RuleId: "id2"}},
		},
	}

	tests := []struct {
		name                 string
		initialPolicyControl []nfConfigApi.PolicyControl
		initialPccPolicies   map[models.Snssai]*PccPolicy
		input                []nfConfigApi.PolicyControl
		expectedPccPolicies  map[models.Snssai]*PccPolicy
	}{
		{
			name:                 "New config has different snssai",
			initialPolicyControl: pc1,
			initialPccPolicies: map[models.Snssai]*PccPolicy{
				{Sst: 1}: {PccRules: map[string]*models.PccRule{
					"id1": {},
				}},
			},
			input: newSnssaiPc,
			expectedPccPolicies: map[models.Snssai]*PccPolicy{
				{Sst: 2}: {
					PccRules: map[string]*models.PccRule{
						"id1": {
							PccRuleId:  "1",
							RefQosData: []string{"1"},
							FlowInfos:  make([]models.FlowInformation, 0),
							RefTcData:  make([]string, 0),
						},
					},
					TraffContDecs: make(map[string]*models.TrafficControlData),
					QosDecs:       map[string]*models.QosData{"1": {QosId: "1", Arp: &models.Arp{PriorityLevel: 0}}},
				},
			},
		},
		{
			name:                 "New config has different pcc Rules",
			initialPolicyControl: pc1,
			initialPccPolicies: map[models.Snssai]*PccPolicy{
				{Sst: 1}: {PccRules: map[string]*models.PccRule{
					"id1": {},
				}},
			},
			input: newPccRules,
			expectedPccPolicies: map[models.Snssai]*PccPolicy{
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
					QosDecs:       map[string]*models.QosData{"1": {QosId: "1", Arp: &models.Arp{PriorityLevel: 0}}},
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

			poller.handlePolledPolicyControl(tc.input)

			if !reflect.DeepEqual(poller.currentPolicyControl, tc.input) {
				t.Errorf("expected current policy control config: %+v, got: %+v",
					tc.input, poller.currentPolicyControl)
			}
			if !reflect.DeepEqual(pccPolicies, tc.expectedPccPolicies) {
				t.Errorf("expected pcc policies config: %+v, got: %+v",
					tc.expectedPccPolicies, pccPolicies)
			}
		})
	}
}

func TestFetchPlmnConfig(t *testing.T) {
	validPolicyControl := []nfConfigApi.PolicyControl{
		{
			PlmnId:   nfConfigApi.PlmnId{Mcc: "001", Mnc: "01"},
			Snssai:   nfConfigApi.Snssai{Sst: 1},
			PccRules: []nfConfigApi.PccRule{},
		},
	}
	validJson, err := json.Marshal(validPolicyControl)
	if err != nil {
		t.Fail()
	}

	tests := []struct {
		name           string
		statusCode     int
		contentType    string
		responseBody   string
		expectedError  string
		expectedResult []nfConfigApi.PolicyControl
	}{
		{
			name:           "200 OK with valid JSON",
			statusCode:     http.StatusOK,
			contentType:    applicationJson,
			responseBody:   string(validJson),
			expectedError:  "",
			expectedResult: validPolicyControl,
		},
		{
			name:          "200 OK with invalid Content-Type",
			statusCode:    http.StatusOK,
			contentType:   "text/plain",
			responseBody:  string(validJson),
			expectedError: "unexpected Content-Type: got text/plain, want application/json",
		},
		{
			name:          "400 Bad Request",
			statusCode:    http.StatusBadRequest,
			contentType:   applicationJson,
			responseBody:  "",
			expectedError: "server returned 400 error code",
		},
		{
			name:          "500 Internal Server Error",
			statusCode:    http.StatusInternalServerError,
			contentType:   applicationJson,
			responseBody:  "",
			expectedError: "server returned 500 error code",
		},
		{
			name:          "Unexpected Status Code 418",
			statusCode:    http.StatusTeapot,
			contentType:   applicationJson,
			responseBody:  "",
			expectedError: "unexpected status code: 418",
		},
		{
			name:          "200 OK with invalid JSON",
			statusCode:    http.StatusOK,
			contentType:   applicationJson,
			responseBody:  "{invalid-json}",
			expectedError: "failed to parse JSON response:",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			originalPccPolicies := pccPolicies
			defer func() {
				pccPolicies = originalPccPolicies
			}()
			pccPolicies = make(map[models.Snssai]*PccPolicy)
			handler := func(w http.ResponseWriter, r *http.Request) {
				accept := r.Header.Get("Accept")
				if accept != applicationJson {
					t.Fail()
				}
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.statusCode)
				_, err = w.Write([]byte(tc.responseBody))
				if err != nil {
					t.Fail()
				}
			}
			server := httptest.NewServer(http.HandlerFunc(handler))
			pollingChan := make(chan consumer.NfProfileDynamicConfig, 1)
			poller := nfConfigPoller{
				currentPolicyControl:   []nfConfigApi.PolicyControl{},
				currentNfProfileConfig: consumer.NfProfileDynamicConfig{},
				nfProfileConfigChan:    pollingChan,
				client:                 &http.Client{},
			}
			defer server.Close()

			fetchedConfig, err := fetchPolicyControlConfig(&poller, server.URL)

			if tc.expectedError == "" {
				if err != nil {
					t.Errorf("expected no error, got `%v`", err)
				}
				if !reflect.DeepEqual(tc.expectedResult, fetchedConfig) {
					t.Errorf("error in fetched config: expected `%v`, got `%v`", tc.expectedResult, fetchedConfig)
				}
			} else {
				if err == nil {
					t.Errorf("expected error `%v`, got nil", tc.expectedError)
				}
				if !strings.Contains(err.Error(), tc.expectedError) {
					t.Errorf("expected error `%v`, got `%v`", tc.expectedError, err)
				}
			}
		})
	}
}
