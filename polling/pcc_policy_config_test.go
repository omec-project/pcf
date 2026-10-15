// SPDX-FileCopyrightText: 2025 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
/*
 * PCC Policy construction Unit Tests
 *
 */
package polling

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"testing"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/nfConfigApi"
	"github.com/omec-project/pcf/util"
	"github.com/omec-project/util/idgenerator"
)

// pccPoliciesForDebug converts SnssaiKey map keys to strings so the map can be JSON-marshaled for logging.
func pccPoliciesForDebug(policies map[SnssaiKey]*PccPolicy) map[string]*PccPolicy {
	debugMap := make(map[string]*PccPolicy, len(policies))
	for key, policy := range policies {
		debugMap[fmt.Sprintf("%+v", key)] = policy
	}
	return debugMap
}

const (
	testPccRuleId1 = "rule1"
	testQosId1     = "qos1"
	testTcId1      = "tc1"
)

func TestGetSlicePccPolicy_Found(t *testing.T) {
	originalPccPolicies := pccPolicies
	defer func() { pccPolicies = originalPccPolicies }()
	pccPolicies = make(map[SnssaiKey]*PccPolicy)
	snssai := models.Snssai{Sst: 1, Sd: new("010203")}

	testPolicy := &PccPolicy{
		PccRules: map[string]*models.PccRule{
			testPccRuleId1: {PccRuleId: testPccRuleId1},
		},
		QosDecs: map[string]*models.QosData{
			testQosId1: {QosId: testQosId1},
		},
		TraffContDecs: map[string]*models.TrafficControlData{
			testTcId1: {TcId: testTcId1},
		},
	}

	pccPolicies[SnssaiToKey(snssai)] = testPolicy

	result := GetSlicePccPolicy(snssai)
	if !reflect.DeepEqual(testPolicy, result) {
		t.Errorf("expected %+v config, received %+v", testPolicy, result)
	}
}

func TestGetSlicePccPolicy_NotFound(t *testing.T) {
	originalPccPolicies := pccPolicies
	defer func() { pccPolicies = originalPccPolicies }()
	pccPolicies = make(map[SnssaiKey]*PccPolicy)
	snssai := models.Snssai{Sst: 2, Sd: new("040506")}

	result := GetSlicePccPolicy(snssai)

	if result != nil {
		t.Errorf("expected nil when policy not found, got %+v", result)
	}
}

func TestUpdatePolicyControl_EmptyInputClearsPolicies(t *testing.T) {
	originalPccPolicies := pccPolicies

	defer func() { pccPolicies = originalPccPolicies }()
	pccPolicies = make(map[SnssaiKey]*PccPolicy)

	snssai := models.Snssai{Sst: 1, Sd: new("010203")}
	pccPolicies[SnssaiToKey(snssai)] = &PccPolicy{}

	updatePccPolicy([]nfConfigApi.PolicyControl{})

	if len(pccPolicies) != 0 {
		t.Errorf("expected pccPolicies to be empty, got %d entries", len(pccPolicies))
	}
}

func TestUpdatePolicyControl_CreatesPolicies(t *testing.T) {
	originalCreate := createPccPolicies
	originalPccPolicies := pccPolicies
	defer func() {
		createPccPolicies = originalCreate
		pccPolicies = originalPccPolicies
	}()
	pccPolicies = make(map[SnssaiKey]*PccPolicy)
	createPccPolicies = func(idGenerator *idgenerator.IDGenerator, pc nfConfigApi.PolicyControl) {
		snssai := models.Snssai{Sst: 1, Sd: new("abc123")}
		pccPolicies[SnssaiToKey(snssai)] = &PccPolicy{}
	}

	updatePccPolicy([]nfConfigApi.PolicyControl{{}})

	if len(pccPolicies) != 1 {
		t.Errorf("expected 1 entry in pccPolicies, got %d", len(pccPolicies))
	}
}

func TestCreatePccPolicies_OnePolicyControlElement(t *testing.T) {
	originalPccPolicies := pccPolicies
	defer func() { pccPolicies = originalPccPolicies }()
	pccPolicies = make(map[SnssaiKey]*PccPolicy)

	testCases := []struct {
		name               string
		initialPccPolicies map[SnssaiKey]*PccPolicy
	}{
		{
			name:               "empty initial pcc policies",
			initialPccPolicies: map[SnssaiKey]*PccPolicy{},
		},
		{
			name: "not empty initial pcc policies",
			initialPccPolicies: map[SnssaiKey]*PccPolicy{
				{Sst: 1, Sd: "22"}: {
					PccRules: map[string]*models.PccRule{
						testPccRuleId1: {PccRuleId: testPccRuleId1},
					},
					QosDecs: map[string]*models.QosData{
						testQosId1: {QosId: testQosId1},
					},
					TraffContDecs: map[string]*models.TrafficControlData{
						testTcId1: {TcId: testTcId1},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := nfConfigApi.PolicyControl{
				Snssai: nfConfigApi.Snssai{
					Sst: 1,
					Sd:  new("112233"),
				},
				PccRules: []nfConfigApi.PccRule{
					{
						RuleId:     testPccRuleId1,
						Precedence: 255,
						Qos: nfConfigApi.PccQos{
							FiveQi:  9,
							MaxBrUl: new("500Mbps"),
							MaxBrDl: new("1Gbps"),
							Arp: nfConfigApi.Arp{
								PriorityLevel: 5,
								PreemptCap:    nfConfigApi.PREEMPTCAP_MAY_PREEMPT,
								PreemptVuln:   nfConfigApi.PREEMPTVULN_PREEMPTABLE,
							},
						},
						Flows: []nfConfigApi.PccFlow{
							{
								Description: "permit out ip from any to any",
								Direction:   nfConfigApi.DIRECTION_BIDIRECTIONAL,
								Status:      nfConfigApi.STATUS_ENABLED,
							},
						},
					},
				},
			}
			idGenerator := idgenerator.NewGenerator(1, math.MaxInt64)
			createPccPolicies(idGenerator, input)

			snssai := models.Snssai{Sst: 1, Sd: new("112233")}
			flowInformation := models.NewFlowInformation()
			flowInformation.SetFlowDescription("permit out ip from any to any")
			flowInformation.SetPackFiltId("2")
			flowInformation.SetFlowDirection(models.FLOWDIRECTIONRM_BIDIRECTIONAL)
			pccRule := models.NewPccRule("1")
			pccRule.SetPrecedence(255)
			pccRule.SetRefQosData([]string{"1"})
			pccRule.SetRefTcData([]string{"2"})
			pccRule.SetFlowInfos([]models.FlowInformation{*flowInformation})
			arp := models.NewArpWithDefaults()
			arp.SetPriorityLevel(5)
			arp.SetPreemptCap(models.PREEMPTIONCAPABILITY_MAY_PREEMPT)
			arp.SetPreemptVuln(models.PREEMPTIONVULNERABILITY_PREEMPTABLE)
			qosData := models.NewQosData("1")
			qosData.SetVar5qi(9)
			qosData.SetMaxbrUl("500Mbps")
			qosData.SetMaxbrDl("1Gbps")
			qosData.SetArp(*arp)
			trafficControlData := models.NewTrafficControlData("2")
			trafficControlData.SetFlowStatus(models.FLOWSTATUS_ENABLED)

			expectedPccPolicies := map[SnssaiKey]*PccPolicy{
				SnssaiToKey(snssai): {
					PccRules:      map[string]*models.PccRule{testPccRuleId1: pccRule},
					QosDecs:       map[string]*models.QosData{"1": qosData},
					TraffContDecs: map[string]*models.TrafficControlData{"2": trafficControlData},
				},
			}

			if !reflect.DeepEqual(pccPolicies, expectedPccPolicies) {
				t.Errorf("expected %+v got %+v", expectedPccPolicies, pccPolicies)
			}
		})
	}
}

func TestCreatePccPolicies_MultiplePolicyControlElement(t *testing.T) {
	originalPccPolicies := pccPolicies
	defer func() {
		pccPolicies = originalPccPolicies
	}()
	pccPolicies = make(map[SnssaiKey]*PccPolicy)

	input := []nfConfigApi.PolicyControl{
		{
			Snssai: nfConfigApi.Snssai{Sst: 1, Sd: new("112233")},
			PccRules: []nfConfigApi.PccRule{
				{
					RuleId:     "rule55",
					Precedence: 10,
					Qos: nfConfigApi.PccQos{
						FiveQi:  5,
						MaxBrUl: new("200Mbps"),
						MaxBrDl: new("300Mbps"),
						Arp: nfConfigApi.Arp{
							PriorityLevel: 88,
							PreemptCap:    nfConfigApi.PREEMPTCAP_NOT_PREEMPT,
							PreemptVuln:   nfConfigApi.PREEMPTVULN_NOT_PREEMPTABLE,
						},
					},
					Flows: []nfConfigApi.PccFlow{
						{
							Description: "flow-A1",
							Direction:   nfConfigApi.DIRECTION_UPLINK,
							Status:      nfConfigApi.STATUS_ENABLED,
						},
						{
							Description: "permit out ip from any to assigned",
							Direction:   nfConfigApi.DIRECTION_DOWNLINK,
							Status:      nfConfigApi.STATUS_DISABLED,
						},
					},
				},
			},
		},
		{
			Snssai: nfConfigApi.Snssai{Sst: 2, Sd: new("445566")},
			PccRules: []nfConfigApi.PccRule{
				{
					RuleId:     "rule2",
					Precedence: 20,
					Qos: nfConfigApi.PccQos{
						FiveQi: 7,
						Arp: nfConfigApi.Arp{
							PriorityLevel: 3,
							PreemptCap:    nfConfigApi.PREEMPTCAP_MAY_PREEMPT,
							PreemptVuln:   nfConfigApi.PREEMPTVULN_PREEMPTABLE,
						},
					},
					Flows: []nfConfigApi.PccFlow{
						{
							Description: "flow-B1",
							Direction:   nfConfigApi.DIRECTION_BIDIRECTIONAL,
							Status:      nfConfigApi.STATUS_ENABLED_DOWNLINK,
						},
					},
				},
			},
		},
	}

	updatePccPolicy(input)

	if len(pccPolicies) != 2 {
		t.Errorf("expected two pcc policies, got %d", len(pccPolicies))
	}

	snssai1 := models.Snssai{Sst: 1, Sd: new("112233")}
	snssai2 := models.Snssai{Sst: 2, Sd: new("445566")}

	flowInfoA1 := models.NewFlowInformation()
	flowInfoA1.SetFlowDescription("flow-A1")
	flowInfoA1.SetPackFiltId("2")
	flowInfoA1.SetFlowDirection(models.FLOWDIRECTIONRM_UPLINK)
	flowInfoAssigned := models.NewFlowInformation()
	flowInfoAssigned.SetFlowDescription("permit out ip from any to assigned")
	flowInfoAssigned.SetPackFiltId("3")
	flowInfoAssigned.SetFlowDirection(models.FLOWDIRECTIONRM_DOWNLINK)

	pccRule55 := models.NewPccRule("1")
	pccRule55.SetPrecedence(10)
	pccRule55.SetRefQosData([]string{"1"})
	pccRule55.SetRefTcData([]string{"2", "3"})
	pccRule55.SetFlowInfos([]models.FlowInformation{*flowInfoA1, *flowInfoAssigned})

	arp1 := models.NewArpWithDefaults()
	arp1.SetPriorityLevel(88)
	arp1.SetPreemptCap(models.PREEMPTIONCAPABILITY_NOT_PREEMPT)
	arp1.SetPreemptVuln(models.PREEMPTIONVULNERABILITY_NOT_PREEMPTABLE)
	qosData1 := models.NewQosData("1")
	qosData1.SetDefQosFlowIndication(true)
	qosData1.SetVar5qi(5)
	qosData1.SetMaxbrUl("200Mbps")
	qosData1.SetMaxbrDl("300Mbps")
	qosData1.SetArp(*arp1)

	tcData2 := models.NewTrafficControlData("2")
	tcData2.SetFlowStatus(models.FLOWSTATUS_ENABLED)
	tcData3 := models.NewTrafficControlData("3")
	tcData3.SetFlowStatus(models.FLOWSTATUS_DISABLED)

	flowInfoB1 := models.NewFlowInformation()
	flowInfoB1.SetFlowDescription("flow-B1")
	flowInfoB1.SetPackFiltId("5")
	flowInfoB1.SetFlowDirection(models.FLOWDIRECTIONRM_BIDIRECTIONAL)

	pccRule2 := models.NewPccRule("4")
	pccRule2.SetPrecedence(20)
	pccRule2.SetRefQosData([]string{"4"})
	pccRule2.SetRefTcData([]string{"5"})
	pccRule2.SetFlowInfos([]models.FlowInformation{*flowInfoB1})

	arp4 := models.NewArpWithDefaults()
	arp4.SetPriorityLevel(3)
	arp4.SetPreemptCap(models.PREEMPTIONCAPABILITY_MAY_PREEMPT)
	arp4.SetPreemptVuln(models.PREEMPTIONVULNERABILITY_PREEMPTABLE)
	qosData4 := models.NewQosData("4")
	qosData4.SetVar5qi(7)
	qosData4.SetArp(*arp4)

	tcData5 := models.NewTrafficControlData("5")
	tcData5.SetFlowStatus(models.FLOWSTATUS_ENABLED_DOWNLINK)

	expectedPccPolicies := map[SnssaiKey]*PccPolicy{
		SnssaiToKey(snssai1): {
			PccRules:      map[string]*models.PccRule{"rule55": pccRule55},
			QosDecs:       map[string]*models.QosData{"1": qosData1},
			TraffContDecs: map[string]*models.TrafficControlData{"2": tcData2, "3": tcData3},
		},
		SnssaiToKey(snssai2): {
			PccRules:      map[string]*models.PccRule{"rule2": pccRule2},
			QosDecs:       map[string]*models.QosData{"4": qosData4},
			TraffContDecs: map[string]*models.TrafficControlData{"5": tcData5},
		},
	}

	if !util.CompareViaJSON(expectedPccPolicies, pccPolicies) {
		t.Errorf("PccPolicy mismatch")
		expectedJSON, err := json.MarshalIndent(pccPoliciesForDebug(expectedPccPolicies), "", "  ")
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
}
