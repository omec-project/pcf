// SPDX-FileCopyrightText: 2025 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
/*
 * IMSI QoS endpoint Unit Tests
 *
 */
package polling

import (
	"errors"
	"reflect"
	"testing"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/openapi/nfConfigApi"
)

const (
	testValidImsi = "imsi-001010123456789"
	testValidDnn  = "internet"
)

func TestGetImsiSessionRules_Success(t *testing.T) {
	originalFetch := fetchImsiQos
	defer func() { fetchImsiQos = originalFetch }()

	fetchImsiQos = func(pollingEndpoint string) ([]nfConfigApi.ImsiQos, error) {
		return []nfConfigApi.ImsiQos{
			{
				FiveQi:           9,
				ArpPriorityLevel: 7,
				MbrUplink:        "1Gbps",
				MbrDownlink:      "500Mbps",
			},
		}, nil
	}

	result, err := GetImsiSessionRules(testValidDnn, testValidImsi)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	expectedSessionRules := map[string]*models.SessionRule{
		"internet-1": {
			SessRuleId: "internet-1",
			AuthSessAmbr: &models.Ambr{
				Uplink:   "1Gbps",
				Downlink: "500Mbps",
			},
			AuthDefQos: &models.AuthorizedDefaultQos{
				Var5qi: 9,
				Arp:    &models.Arp{PriorityLevel: 7},
			},
		},
	}

	if !reflect.DeepEqual(result, expectedSessionRules) {
		t.Errorf("expected %+v, got %+v", expectedSessionRules, result)
	}
}

func TestGetImsiSessionRules_FetchFails(t *testing.T) {
	originalFetch := fetchImsiQos
	defer func() { fetchImsiQos = originalFetch }()

	fetchImsiQos = func(pollingEndpoint string) ([]nfConfigApi.ImsiQos, error) {
		return nil, errors.New("mock error")
	}

	result, err := GetImsiSessionRules(testValidDnn, testValidImsi)

	if err == nil {
		t.Errorf("expected error, got nil")
	}
	if result != nil {
		t.Errorf("expected no result, got %v", result)
	}
}

func TestGetImsiSessionRules_EmptyQoS(t *testing.T) {
	originalFetch := fetchImsiQos
	defer func() { fetchImsiQos = originalFetch }()

	fetchImsiQos = func(pollingEndpoint string) ([]nfConfigApi.ImsiQos, error) {
		return []nfConfigApi.ImsiQos{}, nil
	}

	result, err := GetImsiSessionRules(testValidDnn, testValidImsi)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty session rule, got %d", len(result))
	}
}

func TestGetImsiSessionRules_InvalidInput(t *testing.T) {
	originalFetch := fetchImsiQos
	defer func() { fetchImsiQos = originalFetch }()

	fetchImsiQos = func(pollingEndpoint string) ([]nfConfigApi.ImsiQos, error) {
		return []nfConfigApi.ImsiQos{}, nil
	}

	testCases := []struct {
		name      string
		inputDnn  string
		inputImsi string
	}{
		{
			name:      "invalid dnn",
			inputDnn:  "",
			inputImsi: testValidImsi,
		},
		{
			name:      "imsi too long",
			inputDnn:  testValidDnn,
			inputImsi: "imsi-00101012345678918",
		},
		{
			name:      "imsi too short",
			inputDnn:  testValidDnn,
			inputImsi: "imsi-00101012345678",
		},
		{
			name:      "imsi with a prefix",
			inputDnn:  testValidDnn,
			inputImsi: "001010123456789",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := GetImsiSessionRules(tc.inputDnn, tc.inputImsi)
			if err == nil {
				t.Error("expected error, got nil")
			}
			if result != nil {
				t.Errorf("expected no result, got %+v", result)
			}
		})
	}
}
