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
	"reflect"
	"testing"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/openapi/nfConfigApi"
	"github.com/omec-project/util/idgenerator"
)

func TestGetSlicePccPolicy_Found(t *testing.T) {
	originalPccPolicies := pcfPccPolicies
	defer func() { pcfPccPolicies = originalPccPolicies }()
	pcfPccPolicies = make(map[models.Snssai]*PccPolicy)
	snssai := models.Snssai{Sst: 1, Sd: "010203"}

	sessionRule := &models.SessionRule{
		SessRuleId: "sess-001",
		AuthDefQos: &models.AuthorizedDefaultQos{
			Var5qi: 5,
			Arp: &models.Arp{
				PriorityLevel: 8,
			},
		},
		AuthSessAmbr: &models.Ambr{
			Uplink:   "1Gbps",
			Downlink: "500Mbps",
		},
	}

	testPolicy := &PccPolicy{
		PccRules: map[string]*models.PccRule{
			"rule1": {PccRuleId: "rule1"},
		},
		QosDecs: map[string]*models.QosData{
			"qos1": {QosId: "qos1"},
		},
		TraffContDecs: map[string]*models.TrafficControlData{
			"tc1": {TcId: "tc1"},
		},
		SessionPolicy: map[string]*SessionPolicy{
			"internet": {
				SessionRules: map[string]*models.SessionRule{
					"sr-1": sessionRule,
				},
				SessionRuleIdGenerator: idgenerator.NewGenerator(1, 1000),
			},
		},
		IdGenerator: idgenerator.NewGenerator(1, 1000),
	}

	pcfPccPolicies[snssai] = testPolicy

	result := GetSlicePccPolicy(snssai)
	if !reflect.DeepEqual(testPolicy, result) {
		t.Errorf("Expected %+v config, received %+v", testPolicy, result)
	}
}

func TestGetSlicePccPolicy_NotFound(t *testing.T) {
	originalPccPolicies := pcfPccPolicies
	defer func() { pcfPccPolicies = originalPccPolicies }()
	pcfPccPolicies = make(map[models.Snssai]*PccPolicy)
	snssai := models.Snssai{Sst: 2, Sd: "040506"}

	result := GetSlicePccPolicy(snssai)

	if result != nil {
		t.Errorf("expected nil when policy not found, got %+v", result)
	}
}

func TestUpdatePolicyControl_EmptyInputClearsPolicies(t *testing.T) {
	originalPccPolicies := pcfPccPolicies
	defer func() { pcfPccPolicies = originalPccPolicies }()
	pcfPccPolicies = make(map[models.Snssai]*PccPolicy)
	snssai := models.Snssai{Sst: 1, Sd: "010203"}
	configLock.Lock()
	pcfPccPolicies[snssai] = &PccPolicy{}
	configLock.Unlock()

	updatePolicyControl([]nfConfigApi.PolicyControl{})

	if len(pcfPccPolicies) != 0 {
		t.Errorf("expected pcfPccPolicies to be empty, got %d entries", len(pcfPccPolicies))
	}
}

func TestUpdatePolicyControl_CreatesPolicies(t *testing.T) {
	originalCreate := createpcfPccPoliciesFunc
	defer func() { createpcfPccPoliciesFunc = originalCreate }()
	pcfPccPolicies = make(map[models.Snssai]*PccPolicy)

	createpcfPccPoliciesFunc = func(pc nfConfigApi.PolicyControl) {
		configLock.Lock()
		defer configLock.Unlock()
		snssai := models.Snssai{Sst: 1, Sd: "abc123"}
		pcfPccPolicies[snssai] = &PccPolicy{}
	}

	updatePolicyControl([]nfConfigApi.PolicyControl{{}})

	if len(pcfPccPolicies) != 1 {
		t.Errorf("expected 1 entry in pcfPccPolicies, got %d", len(pcfPccPolicies))
	}
}
