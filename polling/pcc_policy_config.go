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
	pcfPccPolicies map[models.Snssai]*PccPolicy
	configLock     sync.RWMutex
)

//type SessionPolicy struct {
//	SessionRules           map[string]*models.SessionRule
//	SessionRuleIdGenerator *idgenerator.IDGenerator
//}

type PccPolicy struct {
	PccRules      map[string]*models.PccRule
	QosDecs       map[string]*models.QosData
	TraffContDecs map[string]*models.TrafficControlData
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
		logger.PollConfigLog.Warn("received empty Policy Control config. Clearing PCC Policy data")
		pcfPccPolicies = make(map[models.Snssai]*PccPolicy, 0)
		return
	}
	idGenerator := idgenerator.NewGenerator(1, math.MaxInt64)
	for _, pc := range policyControlConfig {
		createPccPolicies(idGenerator, pc)
	}
}

var createPccPolicies = func(idGenerator *idgenerator.IDGenerator, policyControlConfig nfConfigApi.PolicyControl) {
	if len(policyControlConfig.PccRules) == 0 {
		logger.PollConfigLog.Warn("No PCC rules provided in PolicyControl config")
		return
	}
	snssai := models.Snssai{
		Sst: policyControlConfig.Snssai.Sst,
	}
	if sd, ok := policyControlConfig.Snssai.GetSdOk(); ok {
		snssai.Sd = *sd
	}
	pccPolicy := makePccPolicy(idGenerator, policyControlConfig.PccRules)
	jsonData, _ := json.MarshalIndent(pccPolicy, "", "  ")
	logger.PollConfigLog.Errorf("OBTAINED: %s", string(jsonData))
	pcfPccPolicies[snssai] = pccPolicy
}

func makePccPolicy(idGenerator *idgenerator.IDGenerator, pccRules []nfConfigApi.PccRule) (pccPolicy *PccPolicy) {
	pccPolicy = &PccPolicy{
		TraffContDecs: make(map[string]*models.TrafficControlData),
		QosDecs:       make(map[string]*models.QosData),
		PccRules:      make(map[string]*models.PccRule),
	}
	for _, pccrule := range pccRules {
		id, err := idGenerator.Allocate()
		if err != nil {
			logger.PollConfigLog.Errorf("IdGenerator allocation failed: %v", err)
			continue
		}

		flowInfos, traffContDecs := makeFlowInfosAndTrafficContDesc(idGenerator, pccrule.Flows)
		refTcData := make([]string, 0, len(traffContDecs))
		for _, tcData := range traffContDecs {
			refTcData = append(refTcData, tcData.TcId)
			pccPolicy.TraffContDecs[tcData.TcId] = &tcData
		}

		qos := makeQosDesc(id, pccrule.Qos)
		if hasDefaultQosFlow(flowInfos) {
			qos.DefQosFlowIndication = true
		}
		pccPolicy.QosDecs[qos.QosId] = &qos

		rule := models.PccRule{
			PccRuleId:  strconv.FormatInt(id, 10),
			Precedence: pccrule.Precedence,
			FlowInfos:  flowInfos,
			RefTcData:  refTcData,
			RefQosData: []string{qos.QosId},
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
			logger.PollConfigLog.Errorf("IdGenerator allocation failed: %v", err)
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
		case nfConfigApi.STATUS_ENABLED_UPLINK:
			status = models.FlowStatus_ENABLED_UPLINK
		case nfConfigApi.STATUS_ENABLED_DOWNLINK:
			status = models.FlowStatus_ENABLED_DOWNLINK
		case nfConfigApi.STATUS_REMOVED:
			status = models.FlowStatus_REMOVED
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

/*
func (subs PcfSubscriberPolicyData) String() string {
	var s string
	for slice, val := range subs.PccPolicy {
		s += fmt.Sprintf("PccPolicy[%v]: %v", slice, val)
		for rulename, rule := range val.PccRules {
			s += fmt.Sprintf("\n   PccRules[%v]: ", rulename)
			s += fmt.Sprintf("RuleId: %v, Precedence: %v, ", rule.PccRuleId, rule.Precedence)
			for i, flow := range rule.FlowInfos {
				s += fmt.Sprintf("FlowInfo[%v]: FlowDesc: %v, TrafficClass: %v, FlowDir: %v", i, flow.FlowDescription, flow.TosTrafficClass, flow.FlowDirection)
			}
		}
		for i, qos := range val.QosDecs {
			s += fmt.Sprintf("\n   QosDecs[%v] ", i)
			s += fmt.Sprintf("QosId: %v, 5Qi: %v, MaxbrUl: %v, MaxbrDl: %v, GbrUl: %v, GbrUl: %v,PL: %v ", qos.QosId, qos.Var5qi, qos.MaxbrUl, qos.MaxbrDl, qos.GbrDl, qos.GbrUl, qos.PriorityLevel)
			if qos.Arp != nil {
				s += fmt.Sprintf("PL: %v, PC: %v, PV: %v", qos.Arp.PriorityLevel, qos.Arp.PreemptCap, qos.Arp.PreemptVuln)
			}
		}
		for i, tr := range val.TraffContDecs {
			s += fmt.Sprintf("\n   TrafficDecs[%v]: ", i)
			s += fmt.Sprintf("TcId: %v, FlowStatus: %v", tr.TcId, tr.FlowStatus)
		}
	}
	return s
}


func (pcc PccPolicy) String() string {
	var s string
	for name, srule := range pcc.SessionPolicy {
		s += fmt.Sprintf("\n   SessionPolicy[%v]: %v ", name, srule)
	}
	return s
}

func (sess SessionPolicy) String() string {
	var s string
	for name, srule := range sess.SessionRules {
		s += fmt.Sprintf("\n    SessRule[%v]: SessionRuleId: %v, ", name, srule.SessRuleId)
		if srule.AuthDefQos != nil {
			s += fmt.Sprintf("AuthQos: 5Qi: %v, Arp: ", srule.AuthDefQos.Var5qi)
			if srule.AuthDefQos.Arp != nil {
				s += fmt.Sprintf("PL: %v, PC: %v, PV: %v", srule.AuthDefQos.Arp.PriorityLevel, srule.AuthDefQos.Arp.PreemptCap, srule.AuthDefQos.Arp.PreemptVuln)
			}
		}
		if srule.AuthSessAmbr != nil {
			s += fmt.Sprintf("AuthSessAmbr: Uplink: %v, Downlink: %v", srule.AuthSessAmbr.Uplink, srule.AuthSessAmbr.Downlink)
		}
	}
	return s
}

func (c *PCFContext) DisplayPcfSubscriberPolicyData(imsi string) {
	logger.PollConfigLog.Infof("pcf subscriber [%v] Policy Details:", imsi)
	subs, exist := pcfCtx.PcfSubscriberPolicyData[imsi]
	if !exist {
		logger.PollConfigLog.Warnf("pcf subscriber [%v] not exist", imsi)
	} else {
		for slice, val := range subs.PccPolicy {
			subs.CtxLog.Infof("   SliceId: %v", slice)
			for name, srule := range val.SessionPolicy {
				subs.CtxLog.Infof("   Session-Name/Dnn: %v", name)
				for _, srules := range srule.SessionRules {
					subs.CtxLog.Infof("   SessionRuleId: %v", srules.SessRuleId)
					if srules.AuthSessAmbr != nil {
						subs.CtxLog.Infof("   AmbrUplink  %v", srules.AuthSessAmbr.Uplink)
						subs.CtxLog.Infof("   AmbrDownlink  %v", srules.AuthSessAmbr.Downlink)
					}
					if srules.AuthDefQos != nil {
						subs.CtxLog.Infof("    DefQos.5qi: %v", srules.AuthDefQos.Var5qi)
						if srules.AuthDefQos.Arp != nil {
							subs.CtxLog.Infof("    DefQos.Arp.PriorityLevel: %v", srules.AuthDefQos.Arp.PriorityLevel)
							subs.CtxLog.Infof("    DefQos.Arp.PreemptCapability: %v", srules.AuthDefQos.Arp.PreemptCap)
							subs.CtxLog.Infof("    DefQos.Arp.PreemptVulnerability: %v", srules.AuthDefQos.Arp.PreemptVuln)
						}
						subs.CtxLog.Infof("    DefQos.prioritylevel: %v", srules.AuthDefQos.PriorityLevel)
					}
				}
			}
			for rulename, rule := range val.PccRules {
				subs.CtxLog.Infof("   PccRule-Name: %v", rulename)
				subs.CtxLog.Infof("   PccRule-Id: %v", rule.PccRuleId)
				subs.CtxLog.Infof("   Precedence: %v", rule.Precedence)

				for _, flow := range rule.FlowInfos {
					subs.CtxLog.Infof("   FlowDescription: %v", flow.FlowDescription)
					subs.CtxLog.Infof("   TosTrafficClass: %v", flow.TosTrafficClass)
					subs.CtxLog.Infof("   FlowDirection: %v", flow.FlowDirection)
				}
			}
			subs.CtxLog.Infof("   Qos Details")
			for _, qos := range val.QosDecs {
				subs.CtxLog.Infof("     QosId: %v", qos.QosId)
				subs.CtxLog.Infof("     5qi: %v", qos.Var5qi)
				subs.CtxLog.Infof("     MaxbrUl: %v", qos.MaxbrUl)
				subs.CtxLog.Infof("     MaxbrDl: %v", qos.MaxbrDl)
				subs.CtxLog.Infof("     GbrDl: %v", qos.GbrDl)
				subs.CtxLog.Infof("     GbrUl: %v", qos.GbrUl)
				subs.CtxLog.Infof("     PriorityLevel: %v", qos.PriorityLevel)
				if qos.Arp != nil {
					subs.CtxLog.Infof("    Arp.PreemptCapability: %v", qos.Arp.PreemptCap)
					subs.CtxLog.Infof("    Arp.PreemptVulnerability: %v", qos.Arp.PreemptVuln)
				}
			}

			subs.CtxLog.Infof("   Traffic Control Details")
			for _, t := range val.TraffContDecs {
				subs.CtxLog.Infof("     TcId: %v", t.TcId)
				subs.CtxLog.Infof("     FlowStatus: %v", t.FlowStatus)
			}
		}
	}
}*/
