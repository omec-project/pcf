// SPDX-FileCopyrightText: 2025 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
/*
 * SM Policy Unit Tests
 *
 */

package producer

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/nfConfigApi"
	"github.com/omec-project/pcf/factory"
	"github.com/omec-project/pcf/polling"
	"github.com/omec-project/pcf/util"
)

var testSnssai = models.Snssai{
	Sst: 1,
	Sd:  openapi.PtrString("010203"),
}

var (
	testDnn  = "internet"
	testImsi = "imsi-001010123456789"
	testAmbr = &models.Ambr{
		Downlink: "500 Mbps",
		Uplink:   "250 Mbps",
	}
)

var testQos = &models.SubscribedDefaultQos{
	Var5qi:        6,
	PriorityLevel: openapi.PtrInt32(8),
	Arp: models.Arp{
		PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(10)),
	},
}

const applicationJson = "application/json"

func TestBuildSmPolicyDecision_FoundInLocalPolicy(t *testing.T) {
	originalGetSlicePccPolicy := getSlicePccPolicy
	originalPcfConfig := factory.PcfConfig
	defer func() {
		getSlicePccPolicy = originalGetSlicePccPolicy
		factory.PcfConfig = originalPcfConfig
	}()

	getSlicePccPolicy = func(snssai models.Snssai) *polling.PccPolicy {
		return &polling.PccPolicy{
			PccRules: map[string]*models.PccRule{
				"rule1": {
					PccRuleId: "rule1",
				},
			},
			QosDecs: map[string]*models.QosData{
				"qos1": {
					QosId: "qos1",
				},
			},
			TraffContDecs: map[string]*models.TrafficControlData{
				"tc1": {
					TcId: "tc1",
				},
			},
		}
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		accept := r.Header.Get("Accept")
		if accept != applicationJson {
			t.Fail()
		}
		w.Header().Set("Content-Type", applicationJson)
		w.WriteHeader(http.StatusOK)
		retrievedSessionRules := []nfConfigApi.ImsiQos{{
			MbrUplink:        "55 Mbps",
			MbrDownlink:      "515 Mbps",
			FiveQi:           7,
			ArpPriorityLevel: 9,
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
			WebuiUri: server.URL,
		},
	}
	decision, problem := buildSmPolicyDecision(testImsi, testSnssai, testDnn, testAmbr, testQos)

	if problem != nil {
		t.Errorf("expected problem details to be nil, but got %+v", problem)
	}
	if decision == nil {
		t.Error("expected decision to be not nil, but got nil")
	}

	qosDecs := map[string]models.QosData{
		"qos1": {
			QosId: "qos1",
		},
	}
	traffContDecs := map[string]models.TrafficControlData{
		"tc1": {
			TcId: "tc1",
		},
	}
	sessRules := map[string]models.SessionRule{
		"internet-1": {
			SessRuleId: "internet-1",
			AuthSessAmbr: &models.Ambr{
				Uplink:   "55 Mbps",
				Downlink: "515 Mbps",
			},
			AuthDefQos: &models.AuthorizedDefaultQos{
				Var5qi: openapi.PtrInt32(7),
				Arp: &models.Arp{
					PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(9)),
					PreemptCap:    models.PREEMPTIONCAPABILITY_NOT_PREEMPT,
					PreemptVuln:   models.PREEMPTIONVULNERABILITY_PREEMPTABLE,
				},
			},
		},
	}

	expectedDecision := &models.SmPolicyDecision{
		PccRules: map[string]models.PccRule{
			"rule1": {
				PccRuleId: "rule1",
			},
		},
		QosDecs:       &qosDecs,
		TraffContDecs: &traffContDecs,
		SessRules:     &sessRules,
		OfflineChOnly: openapi.PtrBool(false),
	}

	if !util.CompareViaJSON(decision, expectedDecision) {
		t.Errorf("SmPolicyDecision mismatch")
		expectedJSON, err := json.MarshalIndent(expectedDecision, "", "  ")
		if err != nil {
			t.Logf("Failed to marshal expected Decision: %v", err)
		} else {
			t.Logf("Expected Decision: %s", expectedJSON)
		}
		actualJSON, err := json.MarshalIndent(decision, "", "  ")
		if err != nil {
			t.Logf("Failed to marshal actual Decision: %v", err)
		} else {
			t.Logf("Actual Decision: %s", actualJSON)
		}
		t.Logf("Expected SmPolicyDecision: %s", expectedJSON)
		t.Logf("Actual SmPolicyDecision: %s", actualJSON)
	}
}

func TestBuildSmPolicyDecision_SlicePolicyNotFound(t *testing.T) {
	originalGetSlicePccPolicy := getSlicePccPolicy
	defer func() { getSlicePccPolicy = originalGetSlicePccPolicy }()

	getSlicePccPolicy = func(snssai models.Snssai) *polling.PccPolicy {
		return nil
	}

	decision, problem := buildSmPolicyDecision(testImsi, testSnssai, testDnn, testAmbr, testQos)

	if problem == nil {
		t.Fatal("expected problem details not to be nil")
	}
	if problem.GetCause() != "USER_UNKNOWN" {
		t.Errorf("expected cause to be %s, but got %s", "USER_UNKNOWN", problem.GetCause())
	}
	if decision != nil {
		t.Errorf("expected decision to be nil, but got %+v", decision)
	}
}

func TestBuildSmPolicyDecision_SessionRulesEmpty(t *testing.T) {
	originalGetSlicePccPolicy := getSlicePccPolicy
	originalPcfConfig := factory.PcfConfig
	defer func() {
		getSlicePccPolicy = originalGetSlicePccPolicy
		factory.PcfConfig = originalPcfConfig
	}()

	getSlicePccPolicy = func(snssai models.Snssai) *polling.PccPolicy {
		return &polling.PccPolicy{
			PccRules:      map[string]*models.PccRule{},
			QosDecs:       map[string]*models.QosData{},
			TraffContDecs: map[string]*models.TrafficControlData{},
		}
	}

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

	decision, problem := buildSmPolicyDecision(testImsi, testSnssai, testDnn, testAmbr, testQos)

	if problem == nil {
		t.Fatal("expected problem details not to be nil")
	}
	if problem.GetCause() != "USER_UNKNOWN" {
		t.Errorf("expected cause to be %s, but got %s", "USER_UNKNOWN", problem.GetCause())
	}
	if decision != nil {
		t.Errorf("expected decision to be nil, but got %+v", decision)
	}
}

func TestBuildSmPolicyDecision_FallbackToDefault(t *testing.T) {
	originalGetSlicePccPolicy := getSlicePccPolicy
	originalPcfConfig := factory.PcfConfig
	defer func() {
		getSlicePccPolicy = originalGetSlicePccPolicy
		factory.PcfConfig = originalPcfConfig
	}()

	testCases := []struct {
		name         string
		inputAmbr    *models.Ambr
		inputQos     *models.SubscribedDefaultQos
		expectedQos  *models.AuthorizedDefaultQos
		expectedAmbr *models.Ambr
	}{
		{
			name:      "fallback with given QoS and ambr",
			inputAmbr: testAmbr,
			inputQos:  testQos,
			expectedQos: &models.AuthorizedDefaultQos{
				Var5qi: openapi.PtrInt32(6),
				Arp: &models.Arp{
					PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(10)),
				},
				AverWindow: *openapi.NewNullableInt32(openapi.PtrInt32(2000)),
			},
			expectedAmbr: &models.Ambr{
				Downlink: "500 Mbps",
				Uplink:   "250 Mbps",
			},
		},
		{
			name:      "fallback without QoS nor ambr",
			inputAmbr: nil,
			inputQos:  nil,
			expectedQos: &models.AuthorizedDefaultQos{
				Var5qi: openapi.PtrInt32(5),
				Arp: &models.Arp{
					PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(1)),
				},
				AverWindow: *openapi.NewNullableInt32(openapi.PtrInt32(2000)),
			},
			expectedAmbr: &models.Ambr{
				Downlink: "1 Mbps",
				Uplink:   "1 Mbps",
			},
		},
		{
			name:      "fallback with QoS but no ambr",
			inputAmbr: nil,
			inputQos:  testQos,
			expectedQos: &models.AuthorizedDefaultQos{
				Var5qi: openapi.PtrInt32(5),
				Arp: &models.Arp{
					PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(1)),
				},
				AverWindow: *openapi.NewNullableInt32(openapi.PtrInt32(2000)),
			},
			expectedAmbr: &models.Ambr{
				Downlink: "1 Mbps",
				Uplink:   "1 Mbps",
			},
		},
		{
			name:      "fallback without QoS but with ambr",
			inputAmbr: testAmbr,
			inputQos:  nil,
			expectedQos: &models.AuthorizedDefaultQos{
				Var5qi: openapi.PtrInt32(5),
				Arp: &models.Arp{
					PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(1)),
				},
				AverWindow: *openapi.NewNullableInt32(openapi.PtrInt32(2000)),
			},
			expectedAmbr: &models.Ambr{
				Downlink: "1 Mbps",
				Uplink:   "1 Mbps",
			},
		},
	}

	getSlicePccPolicy = func(snssai models.Snssai) *polling.PccPolicy {
		return &polling.PccPolicy{
			PccRules: map[string]*models.PccRule{
				"rule1": {PccRuleId: "rule1"},
			},
			QosDecs: map[string]*models.QosData{
				"qos1": {QosId: "qos1"},
			},
			TraffContDecs: map[string]*models.TrafficControlData{
				"tc1": {TcId: "tc1"},
			},
		}
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
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

			decision, problem := buildSmPolicyDecision(testImsi, testSnssai, testDnn, tc.inputAmbr, tc.inputQos)

			if problem != nil {
				t.Errorf("expected problem details to be nil, but got %+v", problem)
			}
			if decision == nil {
				t.Error("expected decision to be not nil, but got nil")
			}

			qosDecs := map[string]models.QosData{
				"qos1": {
					QosId: "qos1",
				},
			}
			traffContDecs := map[string]models.TrafficControlData{
				"tc1": {
					TcId: "tc1",
				},
			}
			sessRules := map[string]models.SessionRule{
				"internet-1": {
					SessRuleId:   "internet-1",
					AuthDefQos:   tc.expectedQos,
					AuthSessAmbr: tc.expectedAmbr,
				},
			}

			expectedDecision := &models.SmPolicyDecision{
				PccRules: map[string]models.PccRule{
					"rule1": {
						PccRuleId: "rule1",
					},
				},
				QosDecs:       &qosDecs,
				TraffContDecs: &traffContDecs,
				SessRules:     &sessRules,
				OfflineChOnly: openapi.PtrBool(false),
			}

			if !util.CompareViaJSON(decision, expectedDecision) {
				t.Errorf("SmPolicyDecision mismatch")
				expectedJSON, err := json.MarshalIndent(expectedDecision, "", "  ")
				if err != nil {
					t.Logf("Failed to marshal expected Decision: %v", err)
				} else {
					t.Logf("Expected Decision: %s", expectedJSON)
				}
				actualJSON, err := json.MarshalIndent(decision, "", "  ")
				if err != nil {
					t.Logf("Failed to marshal actual Decision: %v", err)
				} else {
					t.Logf("Actual Decision: %s", actualJSON)
				}
				t.Logf("Expected SmPolicyDecision: %s", expectedJSON)
				t.Logf("Actual SmPolicyDecision: %s", actualJSON)
			}
		})
	}
}
