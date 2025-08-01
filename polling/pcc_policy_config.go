// SPDX-FileCopyrightText: 2025 Canonical Ltd

// SPDX-License-Identifier: Apache-2.0
//

package polling

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/openapi/nfConfigApi"
	"github.com/omec-project/pcf/logger"
	"github.com/omec-project/util/idgenerator"
)

var (
	pcfPccPolicies map[models.Snssai]*PccPolicy // Snssai is key
	configLock     sync.RWMutex
)

type SessionPolicy struct {
	SessionRules           map[string]*models.SessionRule
	SessionRuleIdGenerator *idgenerator.IDGenerator
}

type PccPolicy struct {
	PccRules      map[string]*models.PccRule
	QosDecs       map[string]*models.QosData
	TraffContDecs map[string]*models.TrafficControlData
	SessionPolicy map[string]*SessionPolicy // dnn is key
	IdGenerator   *idgenerator.IDGenerator
}

func GetSlicePccPolicy(snssai models.Snssai) *PccPolicy {
	configLock.RLock()
	defer configLock.RUnlock()
	slicePccPolicyData, ok := pcfPccPolicies[snssai]
	if ok {
		return slicePccPolicyData
	}
	return nil
}

func updatePolicyControl(policyControlConfig []nfConfigApi.PolicyControl) {
	configLock.Lock()
	defer configLock.Unlock()
	if len(policyControlConfig) == 0 {
		logger.CtxLog.Warn("received empty Policy Control config. Clearing PCC Policy data")
		pcfPccPolicies = make(map[models.Snssai]*PccPolicy, 0)
		return
	}
	for i, pc := range policyControlConfig {
		logger.CtxLog.Warnf("POLICY CONTROL %d: %+v", i, pc)
		createpcfPccPoliciesFunc(pc)
	}
}

var createpcfPccPoliciesFunc = createpcfPccPolicies

func createpcfPccPolicies(policyControlConfig nfConfigApi.PolicyControl) {
	snssai := models.Snssai{
		Sst: policyControlConfig.Snssai.Sst,
	}
	if sd, ok := policyControlConfig.Snssai.GetSdOk(); ok {
		snssai.Sd = *sd
	}
	pcfPccPolicies[snssai] = &PccPolicy{
		PccRules:      make(map[string]*models.PccRule),
		QosDecs:       make(map[string]*models.QosData),
		TraffContDecs: make(map[string]*models.TrafficControlData),
		SessionPolicy: make(map[string]*SessionPolicy),
		IdGenerator:   nil,
	}
	// pcfPccPolicies[snssai].SessionPolicy = makeSessionPolicies(policyControlConfig.DnnQos)

	pccPolicy := makePccPolicy(policyControlConfig.PccRules)
	jsonData, _ := json.MarshalIndent(pccPolicy, "", "  ")
	logger.CtxLog.Errorf("OBTAINED: %s", string(jsonData))
	for index, element := range pccPolicy.PccRules {
		pcfPccPolicies[snssai].PccRules[index] = element
	}
	for index, element := range pccPolicy.QosDecs {
		pcfPccPolicies[snssai].QosDecs[index] = element
	}
	for index, element := range pccPolicy.TraffContDecs {
		pcfPccPolicies[snssai].TraffContDecs[index] = element
	}
	pcfPccPolicies[snssai].IdGenerator = pccPolicy.IdGenerator
}

/*
func makeSessionPolicies(dnnQos []nfConfigApi.DnnQos) map[string]*SessionPolicy {
	sessionPolicies := map[string]*SessionPolicy{}
	for _, dnnQoS := range dnnQos {
		dnn := dnnQoS.DnnName
		sessionPolicy, ok := sessionPolicies[dnn]
		if !ok {
			sessionPolicy = &SessionPolicy{
				SessionRules:           make(map[string]*models.SessionRule),
				SessionRuleIdGenerator: idgenerator.NewGenerator(1, math.MaxInt16),
			}
			sessionPolicies[dnn] = sessionPolicy
		}

		id, err := sessionPolicy.SessionRuleIdGenerator.Allocate()
		if err != nil {
			logger.CtxLog.Errorf("SessionRuleIdGenerator allocation failed: %v", err)
			continue
		}
		sessionRule := makeSessionRule(dnnQoS)
		sessionRule.SessRuleId = dnn + "-" + strconv.Itoa(int(id))
		sessionPolicies[dnn].SessionRules[sessionRule.SessRuleId] = sessionRule
	}
	return sessionPolicies
}

func makeSessionRule(dnnQoS nfConfigApi.DnnQos) *models.SessionRule {
	var fiveQi int32
	var arp *models.Arp

	if dnnQoS.FiveQi != nil {
		fiveQi = *dnnQoS.FiveQi
	}
	if dnnQoS.ArpPriorityLevel != nil {
		arp = &models.Arp{PriorityLevel: *dnnQoS.ArpPriorityLevel}
	}
	return &models.SessionRule{
		AuthDefQos: &models.AuthorizedDefaultQos{
			Var5qi: fiveQi,
			Arp:    arp,
		},
		AuthSessAmbr: &models.Ambr{
			Uplink:   dnnQoS.MbrUplink,
			Downlink: dnnQoS.MbrDownlink,
		},
	}
}*/

func makePccPolicy(pccRules []nfConfigApi.PccRule) (pccPolicy *PccPolicy) {
	pccPolicy = &PccPolicy{
		IdGenerator:   idgenerator.NewGenerator(1, math.MaxInt64),
		TraffContDecs: make(map[string]*models.TrafficControlData),
		QosDecs:       make(map[string]*models.QosData),
		PccRules:      make(map[string]*models.PccRule),
	}
	for _, pccrule := range pccRules {
		id, err := pccPolicy.IdGenerator.Allocate()
		if err != nil {
			logger.CtxLog.Errorf("IdGenerator allocation failed: %v", err)
			continue
		}

		flowInfos, traffContDecs := makeFlowInfosAndTrafficContDesc(pccPolicy.IdGenerator, pccrule.Flows)
		refTcData := []string{}
		for _, tcData := range traffContDecs {
			refTcData = append(refTcData, tcData.TcId)
			pccPolicy.TraffContDecs[tcData.TcId] = &tcData
		}

		qos := makeQosDesc(id, pccrule.Qos)
		if hasDefaultQosFlow(flowInfos) {
			qos.DefQosFlowIndication = true
		}
		refQosData := []string{}
		if ok, _ := findQosData(pccPolicy.QosDecs, qos); !ok {
			refQosData = append(refQosData, qos.QosId)
			pccPolicy.QosDecs[qos.QosId] = &qos
		}
		rule := models.PccRule{
			PccRuleId:  strconv.FormatInt(id, 10),
			Precedence: pccrule.Precedence,
			FlowInfos:  flowInfos,
			RefTcData:  refTcData,
			RefQosData: refQosData,
		}
		pccPolicy.PccRules[pccrule.RuleId] = &rule
	}
	return pccPolicy
}

func hasDefaultQosFlow(flows []models.FlowInformation) bool {
	for _, flow := range flows {
		desc := strings.TrimSpace(flow.FlowDescription)
		if strings.HasSuffix(desc, "any to assigned") {
			return true
		}
	}
	return false
}

func makeQosDesc(id int64, pccQos nfConfigApi.PccQos) models.QosData {
	qos := models.QosData{
		QosId:   strconv.FormatInt(id, 10),
		Var5qi:  pccQos.FiveQi,
		MaxbrUl: pccQos.MaxBrUl,
		MaxbrDl: pccQos.MaxBrDl,
		Arp:     &models.Arp{PriorityLevel: pccQos.Arp.PriorityLevel},
	}
	switch pccQos.Arp.PreemptCap {
	case nfConfigApi.PREEMPTCAP_NOT_PREEMPT:
		qos.Arp.PreemptCap = models.PreemptionCapability_NOT_PREEMPT
	case nfConfigApi.PREEMPTCAP_MAY_PREEMPT:
		qos.Arp.PreemptCap = models.PreemptionCapability_MAY_PREEMPT
	}
	switch pccQos.Arp.PreemptVuln {
	case nfConfigApi.PREEMPTVULN_NOT_PREEMPTABLE:
		qos.Arp.PreemptVuln = models.PreemptionVulnerability_NOT_PREEMPTABLE
	case nfConfigApi.PREEMPTVULN_PREEMPTABLE:
		qos.Arp.PreemptVuln = models.PreemptionVulnerability_PREEMPTABLE
	}
	return qos
}

func makeFlowInfosAndTrafficContDesc(idGenerator *idgenerator.IDGenerator, pccFlows []nfConfigApi.PccFlow) ([]models.FlowInformation, []models.TrafficControlData) {
	parsedFlows := make([]models.FlowInformation, 0, len(pccFlows))
	parsedTrafficControl := make([]models.TrafficControlData, 0, len(pccFlows))

	for _, pccFlow := range pccFlows {
		id, err := idGenerator.Allocate()
		if err != nil {
			logger.CtxLog.Errorf("IdGenerator allocation failed: %v", err)
			continue
		}

		var direction models.FlowDirectionRm
		switch pccFlow.Direction {
		case nfConfigApi.DIRECTION_DOWNLINK:
			direction = models.FlowDirectionRm_DOWNLINK
		case nfConfigApi.DIRECTION_UPLINK:
			direction = models.FlowDirectionRm_UPLINK
		case nfConfigApi.DIRECTION_BIDIRECTIONAL:
			direction = models.FlowDirectionRm_BIDIRECTIONAL
		case nfConfigApi.DIRECTION_UNSPECIFIED:
			direction = models.FlowDirectionRm_UNSPECIFIED
		default:
			direction = models.FlowDirectionRm_UNSPECIFIED
		}

		flow := models.FlowInformation{
			PackFiltId:      strconv.FormatInt(id, 10),
			FlowDescription: pccFlow.Description,
			FlowDirection:   direction,
		}
		parsedFlows = append(parsedFlows, flow)

		var status models.FlowStatus
		switch pccFlow.Status {
		case nfConfigApi.STATUS_ENABLED:
			status = models.FlowStatus_ENABLED
		case nfConfigApi.STATUS_DISABLED:
			status = models.FlowStatus_DISABLED
		}

		// traffic control info set based on flow at present
		tcData := models.TrafficControlData{
			TcId:       "TcId-" + strconv.FormatInt(id, 10),
			FlowStatus: status,
		}
		parsedTrafficControl = append(parsedTrafficControl, tcData)
	}
	return parsedFlows, parsedTrafficControl
}

func findQosData(qosdecs map[string]*models.QosData, qos models.QosData) (bool, *models.QosData) {
	for _, q := range qosdecs {
		if q.Var5qi == qos.Var5qi && q.MaxbrUl == qos.MaxbrUl && q.MaxbrDl == qos.MaxbrDl &&
			q.GbrUl == qos.GbrUl && q.GbrDl == qos.GbrDl && q.Qnc == qos.Qnc &&
			q.PriorityLevel == qos.PriorityLevel && q.AverWindow == qos.AverWindow &&
			q.MaxDataBurstVol == qos.MaxDataBurstVol && q.ReflectiveQos == qos.ReflectiveQos &&
			q.SharingKeyDl == qos.SharingKeyDl && q.SharingKeyUl == qos.SharingKeyUl &&
			q.MaxPacketLossRateDl == qos.MaxPacketLossRateDl && q.MaxPacketLossRateUl == qos.MaxPacketLossRateUl &&
			q.DefQosFlowIndication == qos.DefQosFlowIndication {
			if q.Arp != nil && qos.Arp != nil && *q.Arp == *qos.Arp {
				return true, q
			}
		}
	}
	return false, nil
}
