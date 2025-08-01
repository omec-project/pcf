// SPDX-FileCopyrightText: 2025 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
/*
 * NRF Registration Unit Testcases
 *
 */
package polling

import (
	"errors"
	"strings"
	"testing"

	"github.com/omec-project/openapi/nfConfigApi"
)

func TestGetImsiSessionRules_Success(t *testing.T) {
	originalFetch := fetchImsiQosFunc
	defer func() { fetchImsiQosFunc = originalFetch }()

	fetchImsiQosFunc = func(pollingEndpoint string) ([]nfConfigApi.ImsiQos, error) {
		return []nfConfigApi.ImsiQos{
			{
				FiveQi:           9,
				ArpPriorityLevel: 7,
				MbrUplink:        "1Gbps",
				MbrDownlink:      "500Mbps",
			},
		}, nil
	}

	dnn := "internet"
	imsi := "imsi-001010123456789"
	result, err := GetImsiSessionRules(dnn, imsi)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected one session rule, got %d", len(result))
	}

	for key, rule := range result {
		if !strings.HasPrefix(key, dnn+"-") {
			t.Errorf("expected key to start with %s, got %s", dnn+"-", key)
		}
		if rule.AuthDefQos == nil {
			t.Errorf("expected AuthDefQos to be non-nil")
		} else {
			if rule.AuthDefQos.Var5qi != 9 {
				t.Errorf("expected Var5qi to be %d, got %d", 9, rule.AuthDefQos.Var5qi)
			}
			if rule.AuthDefQos.Arp == nil {
				t.Errorf("expected ARP to be non-nil")
			} else if rule.AuthDefQos.Arp.PriorityLevel != 7 {
				t.Errorf("expected ARP PriorityLevel to be %d, got %d", 7, rule.AuthDefQos.Arp.PriorityLevel)
			}
		}
		if rule.AuthSessAmbr == nil {
			t.Errorf("expected AuthSessAmbr to be non-nil")
		} else {
			if rule.AuthSessAmbr.Uplink != "1Gbps" {
				t.Errorf("expected Uplink to be '%s', got %q", "1Gbps", rule.AuthSessAmbr.Uplink)
			}
			if rule.AuthSessAmbr.Downlink != "500Mbps" {
				t.Errorf("expected Downlink to be '%s', got %q", "500Mbps", rule.AuthSessAmbr.Downlink)
			}
		}
	}
}

func TestGetImsiSessionRules_FetchFails(t *testing.T) {
	originalFetch := fetchImsiQosFunc
	defer func() { fetchImsiQosFunc = originalFetch }()

	fetchImsiQosFunc = func(pollingEndpoint string) ([]nfConfigApi.ImsiQos, error) {
		return nil, errors.New("mock error")
	}

	dnn := "internet"
	imsi := "001010123456789"
	result, err := GetImsiSessionRules(dnn, imsi)

	if err == nil {
		t.Errorf("expected error, got nil")
	}
	if result != nil {
		t.Errorf("expected no result, got %v", result)
	}
}

func TestGetImsiSessionRules_EmptyQoS(t *testing.T) {
	originalFetch := fetchImsiQosFunc
	defer func() { fetchImsiQosFunc = originalFetch }()

	fetchImsiQosFunc = func(pollingEndpoint string) ([]nfConfigApi.ImsiQos, error) {
		return []nfConfigApi.ImsiQos{}, nil
	}

	dnn := "internet"
	imsi := "001010123456789"
	result, err := GetImsiSessionRules(dnn, imsi)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty session rule, got %d", len(result))
	}
}
