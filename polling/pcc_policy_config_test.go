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
	"math"
	"reflect"
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/nfConfigApi"
	"github.com/omec-project/pcf/util"
	"github.com/omec-project/util/idgenerator"
)

func TestGetSlicePccPolicy_Found(t *testing.T) {
	originalPccPolicies := pccPolicies
	defer func() { pccPolicies = originalPccPolicies }()
	pccPolicies = make(map[SnssaiKey]*PccPolicy)
	snssai := models.Snssai{Sst: 1, Sd: openapi.PtrString("010203")}

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
	snssai := models.Snssai{Sst: 2, Sd: openapi.PtrString("040506")}

	result := GetSlicePccPolicy(snssai)

	if result != nil {
		t.Errorf("expected nil when policy not found, got %+v", result)
	}
}

func TestUpdatePolicyControl_EmptyInputClearsPolicies(t *testing.T) {
	originalPccPolicies := pccPolicies

	defer func() { pccPolicies = originalPccPolicies }()
	pccPolicies = make(map[SnssaiKey]*PccPolicy)

	snssai := models.Snssai{Sst: 1, Sd: openapi.PtrString("010203")}
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
		snssai := models.Snssai{Sst: 1, Sd: openapi.PtrString("abc123")}
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
						"rule1": {PccRuleId: "rule1"},
					},
					QosDecs: map[string]*models.QosData{
						"qos1": {QosId: "qos1"},
					},
					TraffContDecs: map[string]*models.TrafficControlData{
						"tc1": {TcId: "tc1"},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sd := openapi.PtrString("112233")
			input := nfConfigApi.PolicyControl{
				Snssai: nfConfigApi.Snssai{
					Sst: 1,
					Sd:  sd,
				},
				PccRules: []nfConfigApi.PccRule{
					{
						RuleId:     "rule1",
						Precedence: 255,
						Qos: nfConfigApi.PccQos{
							FiveQi:  9,
							MaxBrUl: openapi.PtrString("500Mbps"),
							MaxBrDl: openapi.PtrString("1Gbps"),
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

			snssai := models.Snssai{Sst: 1, Sd: sd}
			expectedPccPolicies := map[SnssaiKey]*PccPolicy{
				SnssaiToKey(snssai): {
					PccRules: map[string]*models.PccRule{
						"rule1": {
							PccRuleId:  "1",
							Precedence: openapi.PtrInt32(255),
							RefQosData: []string{"1"},
							RefTcData:  []string{"TcId-2"},
							FlowInfos: []models.FlowInformation{{
								FlowDescription: openapi.PtrString("permit out ip from any to any"),
								PackFiltId:      openapi.PtrString("2"),
								FlowDirection:   models.FLOWDIRECTIONRM_BIDIRECTIONAL.Ptr(),
							}},
						},
					},
					QosDecs: map[string]*models.QosData{
						"1": {
							QosId:   "1",
							Var5qi:  openapi.PtrInt32(9),
							MaxbrUl: *openapi.NewNullableString(openapi.PtrString("500Mbps")),
							MaxbrDl: *openapi.NewNullableString(openapi.PtrString("1Gbps")),
							Arp: &models.Arp{
								PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(5)),
								PreemptCap:    models.PREEMPTIONCAPABILITY_MAY_PREEMPT,
								PreemptVuln:   models.PREEMPTIONVULNERABILITY_PREEMPTABLE,
							},
						},
					},
					TraffContDecs: map[string]*models.TrafficControlData{
						"TcId-2": {
							TcId:       "TcId-2",
							FlowStatus: models.FLOWSTATUS_ENABLED.Ptr(),
						},
					},
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

	sd1 := openapi.PtrString("112233")
	sd2 := openapi.PtrString("445566")
	input := []nfConfigApi.PolicyControl{
		{
			Snssai: nfConfigApi.Snssai{Sst: 1, Sd: sd1},
			PccRules: []nfConfigApi.PccRule{
				{
					RuleId:     "rule55",
					Precedence: 10,
					Qos: nfConfigApi.PccQos{
						FiveQi:  5,
						MaxBrUl: openapi.PtrString("200Mbps"),
						MaxBrDl: openapi.PtrString("300Mbps"),
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
			Snssai: nfConfigApi.Snssai{Sst: 2, Sd: sd2},
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

	snssai1 := models.Snssai{Sst: 1, Sd: sd1}
	snssai2 := models.Snssai{Sst: 2, Sd: sd2}

	expectedPccPolicies := map[SnssaiKey]*PccPolicy{
		SnssaiToKey(snssai1): {
			PccRules: map[string]*models.PccRule{
				"rule55": {
					PccRuleId:  "1",
					Precedence: openapi.PtrInt32(10),
					RefQosData: []string{"1"},
					RefTcData:  []string{"TcId-2", "TcId-3"},
					FlowInfos: []models.FlowInformation{
						{
							FlowDescription: openapi.PtrString("flow-A1"),
							PackFiltId:      openapi.PtrString("2"),
							FlowDirection:   models.FLOWDIRECTIONRM_UPLINK.Ptr(),
						},
						{
							FlowDescription: openapi.PtrString("permit out ip from any to assigned"),
							PackFiltId:      openapi.PtrString("3"),
							FlowDirection:   models.FLOWDIRECTIONRM_DOWNLINK.Ptr(),
						},
					},
				},
			},
			QosDecs: map[string]*models.QosData{
				"1": {
					QosId:                "1",
					DefQosFlowIndication: openapi.PtrBool(true),
					Var5qi:               openapi.PtrInt32(5),
					MaxbrUl:              *openapi.NewNullableString(openapi.PtrString("200Mbps")),
					MaxbrDl:              *openapi.NewNullableString(openapi.PtrString("300Mbps")),
					Arp: &models.Arp{
						PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(88)),
						PreemptCap:    models.PREEMPTIONCAPABILITY_NOT_PREEMPT,
						PreemptVuln:   models.PREEMPTIONVULNERABILITY_NOT_PREEMPTABLE,
					},
				},
			},
			TraffContDecs: map[string]*models.TrafficControlData{
				"TcId-2": {
					TcId:       "TcId-2",
					FlowStatus: models.FLOWSTATUS_ENABLED.Ptr(),
				},
				"TcId-3": {
					TcId:       "TcId-3",
					FlowStatus: models.FLOWSTATUS_DISABLED.Ptr(),
				},
			},
		},
		SnssaiToKey(snssai2): {
			PccRules: map[string]*models.PccRule{
				"rule2": {
					PccRuleId:  "4",
					Precedence: openapi.PtrInt32(20),
					RefQosData: []string{"4"},
					RefTcData:  []string{"TcId-5"},
					FlowInfos: []models.FlowInformation{{
						FlowDescription: openapi.PtrString("flow-B1"),
						PackFiltId:      openapi.PtrString("5"),
						FlowDirection:   models.FLOWDIRECTIONRM_BIDIRECTIONAL.Ptr(),
					}},
				},
			},
			QosDecs: map[string]*models.QosData{
				"4": {
					QosId:  "4",
					Var5qi: openapi.PtrInt32(7),
					Arp: &models.Arp{
						PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(3)),
						PreemptCap:    models.PREEMPTIONCAPABILITY_MAY_PREEMPT,
						PreemptVuln:   models.PREEMPTIONVULNERABILITY_PREEMPTABLE,
					},
				},
			},
			TraffContDecs: map[string]*models.TrafficControlData{
				"TcId-5": {
					TcId:       "TcId-5",
					FlowStatus: models.FLOWSTATUS_ENABLED_DOWNLINK.Ptr(),
				},
			},
		},
	}

	if !util.CompareViaJSON(expectedPccPolicies, pccPolicies) {
		t.Errorf("PccPolicy mismatch")
		expectedJSON, err := json.MarshalIndent(expectedPccPolicies, "", "  ")
		if err != nil {
			t.Logf("Failed to marshal expected PccPolicy: %v", err)
		} else {
			t.Logf("Expected PccPolicy: %s", expectedJSON)
		}
		actualJSON, err := json.MarshalIndent(pccPolicies, "", "  ")
		if err != nil {
			t.Logf("Failed to marshal actual PccPolicy: %v", err)
		} else {
			t.Logf("Actual PccPolicy: %s", actualJSON)
		}
		t.Logf("Expected PccPolicy: %s", expectedJSON)
		t.Logf("Actual PccPolicy: %s", actualJSON)
	}
}
