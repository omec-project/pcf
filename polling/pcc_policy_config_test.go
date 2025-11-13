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
	"math"
	"reflect"
	"testing"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/openapi/nfConfigApi"
	"github.com/omec-project/util/idgenerator"
)

func TestGetSlicePccPolicy_Found(t *testing.T) {
	originalPccPolicies := pccPolicies
	defer func() { pccPolicies = originalPccPolicies }()
	pccPolicies = make(map[models.Snssai]*PccPolicy)
	snssai := models.Snssai{Sst: 1, Sd: "010203"}

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

	pccPolicies[snssai] = testPolicy

	result := GetSlicePccPolicy(snssai)
	if !reflect.DeepEqual(testPolicy, result) {
		t.Errorf("expected %+v config, received %+v", testPolicy, result)
	}
}

func TestGetSlicePccPolicy_NotFound(t *testing.T) {
	originalPccPolicies := pccPolicies
	defer func() { pccPolicies = originalPccPolicies }()
	pccPolicies = make(map[models.Snssai]*PccPolicy)
	snssai := models.Snssai{Sst: 2, Sd: "040506"}

	result := GetSlicePccPolicy(snssai)

	if result != nil {
		t.Errorf("expected nil when policy not found, got %+v", result)
	}
}

func TestUpdatePolicyControl_EmptyInputClearsPolicies(t *testing.T) {
	originalPccPolicies := pccPolicies

	defer func() { pccPolicies = originalPccPolicies }()
	pccPolicies = make(map[models.Snssai]*PccPolicy)

	snssai := models.Snssai{Sst: 1, Sd: "010203"}
	pccPolicies[snssai] = &PccPolicy{}

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
	pccPolicies = make(map[models.Snssai]*PccPolicy)
	createPccPolicies = func(idGenerator *idgenerator.IDGenerator, pc nfConfigApi.PolicyControl) {
		snssai := models.Snssai{Sst: 1, Sd: "abc123"}
		pccPolicies[snssai] = &PccPolicy{}
	}

	updatePccPolicy([]nfConfigApi.PolicyControl{{}})

	if len(pccPolicies) != 1 {
		t.Errorf("expected 1 entry in pccPolicies, got %d", len(pccPolicies))
	}
}

func TestCreatePccPolicies_OnePolicyControlElement(t *testing.T) {
	originalPccPolicies := pccPolicies
	defer func() { pccPolicies = originalPccPolicies }()
	pccPolicies = make(map[models.Snssai]*PccPolicy)

	testCases := []struct {
		name               string
		initialPccPolicies map[models.Snssai]*PccPolicy
	}{
		{
			name:               "empty initial pcc policies",
			initialPccPolicies: map[models.Snssai]*PccPolicy{},
		},
		{
			name: "not empty initial pcc policies",
			initialPccPolicies: map[models.Snssai]*PccPolicy{
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
			sd := "112233"
			maxBrUl := "500Mbps"
			maxBrDl := "1Gbps"
			input := nfConfigApi.PolicyControl{
				Snssai: nfConfigApi.Snssai{
					Sst: 1,
					Sd:  &sd,
				},
				PccRules: []nfConfigApi.PccRule{
					{
						RuleId:     "rule1",
						Precedence: 255,
						Qos: nfConfigApi.PccQos{
							FiveQi:  9,
							MaxBrUl: &maxBrUl,
							MaxBrDl: &maxBrDl,
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
			expectedPccPolicies := map[models.Snssai]*PccPolicy{
				snssai: {
					PccRules: map[string]*models.PccRule{
						"rule1": {
							PccRuleId:  "1",
							Precedence: 255,
							RefQosData: []string{"1"},
							RefTcData:  []string{"TcId-2"},
							FlowInfos: []models.FlowInformation{{
								FlowDescription: "permit out ip from any to any",
								PackFiltId:      "2",
								FlowDirection:   models.FlowDirectionRm_BIDIRECTIONAL,
							}},
						},
					},
					QosDecs: map[string]*models.QosData{
						"1": {
							QosId:   "1",
							Var5qi:  9,
							MaxbrUl: "500Mbps",
							MaxbrDl: "1Gbps",
							Arp: &models.Arp{
								PriorityLevel: 5,
								PreemptCap:    models.PreemptionCapability_MAY_PREEMPT,
								PreemptVuln:   models.PreemptionVulnerability_PREEMPTABLE,
							},
						},
					},
					TraffContDecs: map[string]*models.TrafficControlData{
						"TcId-2": {
							TcId:       "TcId-2",
							FlowStatus: models.FlowStatus_ENABLED,
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
	pccPolicies = make(map[models.Snssai]*PccPolicy)

	sd1 := "112233"
	sd2 := "445566"
	maxBrUl1 := "200Mbps"
	maxBrDl1 := "300Mbps"
	maxBrUl2 := "100Mbps"
	maxBrDl2 := "150Mbps"
	input := []nfConfigApi.PolicyControl{
		{
			Snssai: nfConfigApi.Snssai{Sst: 1, Sd: &sd1},
			PccRules: []nfConfigApi.PccRule{
				{
					RuleId:     "rule55",
					Precedence: 10,
					Qos: nfConfigApi.PccQos{
						FiveQi:  5,
						MaxBrUl: &maxBrUl1,
						MaxBrDl: &maxBrDl1,
						Arp: nfConfigApi.Arp{
							PriorityLevel: 88,
							PreemptCap:    nfConfigApi.PREEMPTCAP_NOT_PREEMPT,
							PreemptVuln:   nfConfigApi.PREEMPTVULN_NOT_PREEMPTABLE,
						},
					},
					Flows: []nfConfigApi.PccFlow{
						{Description: "flow-A1", Direction: nfConfigApi.DIRECTION_UPLINK, Status: nfConfigApi.STATUS_ENABLED},
						{Description: "permit out ip from any to assigned", Direction: nfConfigApi.DIRECTION_DOWNLINK, Status: nfConfigApi.STATUS_DISABLED},
					},
				},
			},
		},
		{
			Snssai: nfConfigApi.Snssai{Sst: 2, Sd: &sd2},
			PccRules: []nfConfigApi.PccRule{
				{
					RuleId:     "rule2",
					Precedence: 20,
					Qos: nfConfigApi.PccQos{
						FiveQi:  7,
						MaxBrUl: &maxBrUl2,
						MaxBrDl: &maxBrDl2,
						Arp: nfConfigApi.Arp{
							PriorityLevel: 3,
							PreemptCap:    nfConfigApi.PREEMPTCAP_MAY_PREEMPT,
							PreemptVuln:   nfConfigApi.PREEMPTVULN_PREEMPTABLE,
						},
					},
					Flows: []nfConfigApi.PccFlow{
						{Description: "flow-B1", Direction: nfConfigApi.DIRECTION_BIDIRECTIONAL, Status: nfConfigApi.STATUS_ENABLED_DOWNLINK},
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

	expectedPccPolicies := map[models.Snssai]*PccPolicy{
		snssai1: {
			PccRules: map[string]*models.PccRule{
				"rule55": {
					PccRuleId:  "1",
					Precedence: 10,
					RefQosData: []string{"1"},
					RefTcData:  []string{"TcId-2", "TcId-3"},
					FlowInfos: []models.FlowInformation{
						{
							FlowDescription: "flow-A1",
							PackFiltId:      "2",
							FlowDirection:   models.FlowDirectionRm_UPLINK,
						},
						{
							FlowDescription: "permit out ip from any to assigned",
							PackFiltId:      "3",
							FlowDirection:   models.FlowDirectionRm_DOWNLINK,
						},
					},
				},
			},
			QosDecs: map[string]*models.QosData{
				"1": {
					QosId:                "1",
					DefQosFlowIndication: true,
					Var5qi:               5,
					MaxbrUl:              "200Mbps",
					MaxbrDl:              "300Mbps",
					Arp: &models.Arp{
						PriorityLevel: 88,
						PreemptCap:    models.PreemptionCapability_NOT_PREEMPT,
						PreemptVuln:   models.PreemptionVulnerability_NOT_PREEMPTABLE,
					},
				},
			},
			TraffContDecs: map[string]*models.TrafficControlData{
				"TcId-2": {
					TcId:       "TcId-2",
					FlowStatus: models.FlowStatus_ENABLED,
				},
				"TcId-3": {
					TcId:       "TcId-3",
					FlowStatus: models.FlowStatus_DISABLED,
				},
			},
		},
		snssai2: {
			PccRules: map[string]*models.PccRule{
				"rule2": {
					PccRuleId:  "4",
					Precedence: 20,
					RefQosData: []string{"4"},
					RefTcData:  []string{"TcId-5"},
					FlowInfos: []models.FlowInformation{{
						FlowDescription: "flow-B1",
						PackFiltId:      "5",
						FlowDirection:   models.FlowDirectionRm_BIDIRECTIONAL,
					}},
				},
			},
			QosDecs: map[string]*models.QosData{
				"4": {
					QosId:                "4",
					DefQosFlowIndication: false,
					Var5qi:               7,
					MaxbrUl:              "100Mbps",
					MaxbrDl:              "150Mbps",
					Arp: &models.Arp{
						PriorityLevel: 3,
						PreemptCap:    models.PreemptionCapability_MAY_PREEMPT,
						PreemptVuln:   models.PreemptionVulnerability_PREEMPTABLE,
					},
				},
			},
			TraffContDecs: map[string]*models.TrafficControlData{
				"TcId-5": {
					TcId:       "TcId-5",
					FlowStatus: models.FlowStatus_ENABLED_DOWNLINK,
				},
			},
		},
	}

	if !reflect.DeepEqual(pccPolicies, expectedPccPolicies) {
		t.Errorf("expected %+v got %+v", expectedPccPolicies, pccPolicies)
	}
}
