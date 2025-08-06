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
	"fmt"
	"reflect"
	"testing"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/pcf/polling"
)

var testSnssai = models.Snssai{
	Sst: 1,
	Sd:  "010203",
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
	PriorityLevel: 8,
	Arp: &models.Arp{
		PriorityLevel: 10,
	},
}

func TestBuildSmPolicyDecision_FoundInLocalPolicy(t *testing.T) {
	originalGetSlicePccPolicy := polling.GetSlicePccPolicy
	originalGetImsiSessionRules := polling.GetImsiSessionRules
	defer func() {
		polling.GetSlicePccPolicy = originalGetSlicePccPolicy
		polling.GetImsiSessionRules = originalGetImsiSessionRules
	}()

	polling.GetSlicePccPolicy = func(snssai models.Snssai) *polling.PccPolicy {
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

	polling.GetImsiSessionRules = func(dnn, imsi string) (map[string]*models.SessionRule, error) {
		return map[string]*models.SessionRule{
			"sess1": {
				SessRuleId: "sess1",
				AuthSessAmbr: &models.Ambr{
					Uplink:   "55 mpb",
					Downlink: "55 mpb",
				},
			},
		}, nil
	}
	decision, problem := buildSmPolicyDecision(testImsi, testSnssai, testDnn, testAmbr, testQos)

	if problem != nil {
		t.Errorf("expected problem details to be nil, but got %+v", problem)
	}
	if decision == nil {
		t.Error("expected decision to be not nil, but got nil")
	}

	expectedDecision := &models.SmPolicyDecision{
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
		SessRules: map[string]*models.SessionRule{
			"sess1": {
				SessRuleId: "sess1",
				AuthSessAmbr: &models.Ambr{
					Uplink:   "55 mpb",
					Downlink: "55 mpb",
				},
			},
		},
	}

	if !reflect.DeepEqual(decision, expectedDecision) {
		t.Errorf("expected %+v, got %+v", expectedDecision, decision)
	}
}

func TestBuildSmPolicyDecision_SlicePolicyNotFound(t *testing.T) {
	originalGetSlicePccPolicy := polling.GetSlicePccPolicy
	originalGetImsiSessionRules := polling.GetImsiSessionRules
	defer func() {
		polling.GetSlicePccPolicy = originalGetSlicePccPolicy
		polling.GetImsiSessionRules = originalGetImsiSessionRules
	}()

	polling.GetSlicePccPolicy = func(snssai models.Snssai) *polling.PccPolicy {
		return nil
	}

	decision, problem := buildSmPolicyDecision(testImsi, testSnssai, testDnn, testAmbr, testQos)

	if problem == nil {
		t.Fatal("expected problem details not to be nil")
	}
	if problem.Cause != "USER_UNKNOWN" {
		t.Errorf("expected cause to be %s, but got %s", "USER_UNKNOWN", problem.Cause)
	}
	if decision != nil {
		t.Errorf("expected decision to be nil, but got %+v", decision)
	}
}

func TestBuildSmPolicyDecision_SessionRulesEmpty(t *testing.T) {
	originalGetSlicePccPolicy := polling.GetSlicePccPolicy
	originalGetImsiSessionRules := polling.GetImsiSessionRules
	defer func() {
		polling.GetSlicePccPolicy = originalGetSlicePccPolicy
		polling.GetImsiSessionRules = originalGetImsiSessionRules
	}()

	polling.GetSlicePccPolicy = func(snssai models.Snssai) *polling.PccPolicy {
		return &polling.PccPolicy{
			PccRules:      map[string]*models.PccRule{},
			QosDecs:       map[string]*models.QosData{},
			TraffContDecs: map[string]*models.TrafficControlData{},
		}
	}
	polling.GetImsiSessionRules = func(dnn, imsi string) (map[string]*models.SessionRule, error) {
		return map[string]*models.SessionRule{}, nil
	}

	decision, problem := buildSmPolicyDecision(testImsi, testSnssai, testDnn, testAmbr, testQos)

	if problem == nil {
		t.Fatal("expected problem details not to be nil")
	}
	if problem.Cause != "USER_UNKNOWN" {
		t.Errorf("expected cause to be %s, but got %s", "USER_UNKNOWN", problem.Cause)
	}
	if decision != nil {
		t.Errorf("expected decision to be nil, but got %+v", decision)
	}
}

func TestBuildSmPolicyDecision_FallbackToDefault(t *testing.T) {
	originalGetSlicePccPolicy := polling.GetSlicePccPolicy
	originalGetImsiSessionRules := polling.GetImsiSessionRules
	defer func() {
		polling.GetSlicePccPolicy = originalGetSlicePccPolicy
		polling.GetImsiSessionRules = originalGetImsiSessionRules
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
				Var5qi: 6,
				Arp: &models.Arp{
					PriorityLevel: 10,
				},
				PriorityLevel: 8,
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
				Var5qi: 5,
				Arp: &models.Arp{
					PriorityLevel: 1,
				},
				PriorityLevel: 1,
			},
			expectedAmbr: &models.Ambr{
				Downlink: "1000 Kbps",
				Uplink:   "1000 Kbps",
			},
		},
		{
			name:      "fallback with QoS but no ambr",
			inputAmbr: nil,
			inputQos:  testQos,
			expectedQos: &models.AuthorizedDefaultQos{
				Var5qi: 5,
				Arp: &models.Arp{
					PriorityLevel: 1,
				},
				PriorityLevel: 1,
			},
			expectedAmbr: &models.Ambr{
				Downlink: "1000 Kbps",
				Uplink:   "1000 Kbps",
			},
		},
		{
			name:      "fallback without QoS but with ambr",
			inputAmbr: testAmbr,
			inputQos:  nil,
			expectedQos: &models.AuthorizedDefaultQos{
				Var5qi: 5,
				Arp: &models.Arp{
					PriorityLevel: 1,
				},
				PriorityLevel: 1, ////////////////// may be not set
			},
			expectedAmbr: &models.Ambr{
				Downlink: "1000 Kbps",
				Uplink:   "1000 Kbps",
			},
		},
	}

	polling.GetSlicePccPolicy = func(snssai models.Snssai) *polling.PccPolicy {
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
			polling.GetImsiSessionRules = func(dnn, imsi string) (map[string]*models.SessionRule, error) {
				return nil, fmt.Errorf("mock error")
			}

			decision, problem := buildSmPolicyDecision(testImsi, testSnssai, testDnn, tc.inputAmbr, tc.inputQos)

			if problem != nil {
				t.Errorf("expected problem details to be nil, but got %+v", problem)
			}
			if decision == nil {
				t.Error("expected decision to be not nil, but got nil")
			}

			expectedDecision := &models.SmPolicyDecision{
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
				SessRules: map[string]*models.SessionRule{
					"internet-1": {
						SessRuleId:   "internet-1",
						AuthDefQos:   tc.expectedQos,
						AuthSessAmbr: tc.expectedAmbr,
					},
				},
			}

			if !reflect.DeepEqual(decision, expectedDecision) {
				t.Errorf("expected %+v, got %+v", expectedDecision, decision)
			}
		})
	}
}
