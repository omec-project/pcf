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
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/nfConfigApi"
	"github.com/omec-project/pcf/factory"
)

const (
	testValidImsi           = "imsi-001010123456789"
	testValidDnn            = "internet"
	testMbrUplink1Gbps      = "1 Gbps"
	testMbrDownlink500Mbps  = "500 Mbps"
	testSessRuleIdInternet1 = "internet-1"
)

// newExpectedSessionRule builds the SessionRule expected from an ImsiQos config entry.
func newExpectedSessionRule(sessRuleId, mbrUplink, mbrDownlink string, fiveQi, arpPriorityLevel int32) *models.SessionRule {
	sessionRule := models.NewSessionRule(sessRuleId)
	sessionRule.SetAuthSessAmbr(*models.NewAmbr(mbrUplink, mbrDownlink))

	arp := models.NewArpWithDefaults()
	arp.SetPriorityLevel(arpPriorityLevel)
	arp.SetPreemptCap(models.PREEMPTIONCAPABILITY_NOT_PREEMPT)
	arp.SetPreemptVuln(models.PREEMPTIONVULNERABILITY_PREEMPTABLE)
	authDefQos := models.NewAuthorizedDefaultQosWithDefaults()
	authDefQos.SetVar5qi(fiveQi)
	authDefQos.SetArp(*arp)
	sessionRule.SetAuthDefQos(*authDefQos)

	return sessionRule
}

func TestGetImsiSessionRules_Success(t *testing.T) {
	originalPcfConfig := factory.PcfConfig
	defer func() { factory.PcfConfig = originalPcfConfig }()

	testCases := []struct {
		name                 string
		input                []nfConfigApi.ImsiQos
		expectedSessionRules map[string]*models.SessionRule
	}{
		{
			name: "single imsi qos",
			input: []nfConfigApi.ImsiQos{{
				MbrUplink:        testMbrUplink1Gbps,
				MbrDownlink:      testMbrDownlink500Mbps,
				FiveQi:           9,
				ArpPriorityLevel: 2,
			}},
			expectedSessionRules: map[string]*models.SessionRule{
				testSessRuleIdInternet1: newExpectedSessionRule(testSessRuleIdInternet1, testMbrUplink1Gbps, testMbrDownlink500Mbps, 9, 2),
			},
		},
		{
			name: "multiple imsi qos",
			input: []nfConfigApi.ImsiQos{{
				MbrUplink:        testMbrUplink1Gbps,
				MbrDownlink:      testMbrDownlink500Mbps,
				FiveQi:           9,
				ArpPriorityLevel: 2,
			}, {
				MbrUplink:        "2 Mbps",
				MbrDownlink:      "12 Kbps",
				FiveQi:           8,
				ArpPriorityLevel: 1,
			}, {
				MbrUplink:        "17 Gbps",
				MbrDownlink:      "90 Mbps",
				FiveQi:           2,
				ArpPriorityLevel: 7,
			}},
			expectedSessionRules: map[string]*models.SessionRule{
				testSessRuleIdInternet1: newExpectedSessionRule(testSessRuleIdInternet1, testMbrUplink1Gbps, testMbrDownlink500Mbps, 9, 2),
				"internet-2":            newExpectedSessionRule("internet-2", "2 Mbps", "12 Kbps", 8, 1),
				"internet-3":            newExpectedSessionRule("internet-3", "17 Gbps", "90 Mbps", 2, 7),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, r *http.Request) {
				accept := r.Header.Get("Accept")
				if accept != applicationJson {
					t.Fail()
				}
				w.Header().Set("Content-Type", applicationJson)
				w.WriteHeader(http.StatusOK)
				jsonData, err := json.Marshal(tc.input)
				if err != nil {
					log.Println("Error serializing data:", err)
					t.Fail()
					return
				}
				_, err = w.Write(jsonData)
				if err != nil {
					log.Println("Error writing data:", err)
					t.Fail()
				}
			}
			server := httptest.NewServer(http.HandlerFunc(handler))
			defer server.Close()

			factory.PcfConfig = factory.Config{
				Configuration: &factory.Configuration{
					WebuiUri: server.URL,
				},
			}

			result, err := GetImsiSessionRules(testValidDnn, testValidImsi)
			if err != nil {
				t.Errorf("expected no error, got %v", err)
			}
			if !reflect.DeepEqual(result, tc.expectedSessionRules) {
				t.Errorf("expected %+v, got %+v", tc.expectedSessionRules, result)
			}
		})
	}
}

func TestGetImsiSessionRules_FetchFailsDueToUnreachableWebconsole(t *testing.T) {
	originalPcfConfig := factory.PcfConfig
	defer func() { factory.PcfConfig = originalPcfConfig }()

	handler := func(w http.ResponseWriter, r *http.Request) {
		accept := r.Header.Get("Accept")
		if accept != applicationJson {
			t.Fail()
		}
		w.Header().Set("Content-Type", applicationJson)
		w.WriteHeader(http.StatusOK)
		retrievedSessionRules := []nfConfigApi.ImsiQos{{
			MbrUplink:        testMbrUplink1Gbps,
			MbrDownlink:      testMbrDownlink500Mbps,
			FiveQi:           9,
			ArpPriorityLevel: 2,
		}}
		jsonData, err := json.Marshal(retrievedSessionRules)
		if err != nil {
			log.Println("Error serializing data:", err)
			t.Fail()
			return
		}
		_, err = w.Write(jsonData)
		if err != nil {
			log.Println("Error writing data:", err)
			t.Fail()
		}
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	factory.PcfConfig = factory.Config{
		Configuration: &factory.Configuration{
			WebuiUri: "some-wrong-address",
		},
	}

	result, err := GetImsiSessionRules(testValidDnn, testValidImsi)

	if err == nil {
		t.Errorf("expected error, got nil")
	}
	if result != nil {
		t.Errorf("expected no result, got %v", result)
	}
}

func TestGetImsiSessionRules_FetchFailsDueToIncorrectStatusCode(t *testing.T) {
	originalPcfConfig := factory.PcfConfig
	defer func() { factory.PcfConfig = originalPcfConfig }()

	handler := func(w http.ResponseWriter, r *http.Request) {
		accept := r.Header.Get("Accept")
		if accept != applicationJson {
			t.Fail()
		}
		w.Header().Set("Content-Type", applicationJson)
		w.WriteHeader(http.StatusBadRequest)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	factory.PcfConfig = factory.Config{
		Configuration: &factory.Configuration{
			WebuiUri: server.URL,
		},
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
	originalPcfConfig := factory.PcfConfig
	defer func() { factory.PcfConfig = originalPcfConfig }()

	handler := func(w http.ResponseWriter, r *http.Request) {
		accept := r.Header.Get("Accept")
		if accept != applicationJson {
			t.Fail()
		}
		w.Header().Set("Content-Type", applicationJson)
		w.WriteHeader(http.StatusNotFound)
		retrievedSessionRules := []nfConfigApi.ImsiQos{}
		jsonData, err := json.Marshal(retrievedSessionRules)
		if err != nil {
			log.Println("Error serializing data:", err)
			t.Fail()
			return
		}
		_, err = w.Write(jsonData)
		if err != nil {
			log.Println("Error writing data:", err)
			t.Fail()
		}
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	factory.PcfConfig = factory.Config{
		Configuration: &factory.Configuration{
			WebuiUri: server.URL,
		},
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
