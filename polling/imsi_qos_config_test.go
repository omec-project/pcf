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

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/openapi/nfConfigApi"
	"github.com/omec-project/pcf/factory"
)

const (
	testValidImsi = "imsi-001010123456789"
	testValidDnn  = "internet"
)

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
				MbrUplink:        "1 Gbps",
				MbrDownlink:      "500 Mbps",
				FiveQi:           9,
				ArpPriorityLevel: 2,
			}},
			expectedSessionRules: map[string]*models.SessionRule{
				"internet-1": {
					SessRuleId: "internet-1",
					AuthSessAmbr: &models.Ambr{
						Uplink:   "1 Gbps",
						Downlink: "500 Mbps",
					},
					AuthDefQos: &models.AuthorizedDefaultQos{
						Var5qi: 9,
						Arp:    &models.Arp{PriorityLevel: 2},
					},
				},
			},
		},
		{
			name: "multiple imsi qos",
			input: []nfConfigApi.ImsiQos{{
				MbrUplink:        "1 Gbps",
				MbrDownlink:      "500 Mbps",
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
				"internet-1": {
					SessRuleId: "internet-1",
					AuthSessAmbr: &models.Ambr{
						Uplink:   "1 Gbps",
						Downlink: "500 Mbps",
					},
					AuthDefQos: &models.AuthorizedDefaultQos{
						Var5qi: 9,
						Arp:    &models.Arp{PriorityLevel: 2},
					},
				},
				"internet-2": {
					SessRuleId: "internet-2",
					AuthSessAmbr: &models.Ambr{
						Uplink:   "2 Mbps",
						Downlink: "12 Kbps",
					},
					AuthDefQos: &models.AuthorizedDefaultQos{
						Var5qi: 8,
						Arp:    &models.Arp{PriorityLevel: 1},
					},
				},
				"internet-3": {
					SessRuleId: "internet-3",
					AuthSessAmbr: &models.Ambr{
						Uplink:   "17 Gbps",
						Downlink: "90 Mbps",
					},
					AuthDefQos: &models.AuthorizedDefaultQos{
						Var5qi: 2,
						Arp:    &models.Arp{PriorityLevel: 7},
					},
				},
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
			MbrUplink:        "1 Gbps",
			MbrDownlink:      "500 Mbps",
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
		w.WriteHeader(http.StatusOK)
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
