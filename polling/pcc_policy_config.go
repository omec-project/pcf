// SPDX-FileCopyrightText: 2025 Canonical Ltd

// SPDX-License-Identifier: Apache-2.0
//

package polling

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/nfConfigApi"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/logger"
	"github.com/omec-project/util/idgenerator"
)

var (
	pccPolicies map[SnssaiKey]*PccPolicy
	configLock  sync.RWMutex
)

type PccPolicy struct {
	PccRules      map[string]*models.PccRule
	QosDecs       map[string]*models.QosData
	TraffContDecs map[string]*models.TrafficControlData
}

// SnssaiKey is used to avoid using models.Snssai as map key directly due to pointer field issue
type SnssaiKey struct {
	Sst int32
	Sd  string
}

// Helper function to convert models.Snssai to SnssaiKey
func SnssaiToKey(s models.Snssai) SnssaiKey {
	return SnssaiKey{
		Sst: s.GetSst(),
		Sd:  s.GetSd(),
	}
}

func GetSlicePccPolicy(snssai models.Snssai) *PccPolicy {
	configLock.RLock()
	defer configLock.RUnlock()
	slicePccPolicyData, ok := pccPolicies[SnssaiToKey(snssai)]
	if ok {
		return slicePccPolicyData
	}
	return nil
}

func updatePccPolicy(policyControlConfig []nfConfigApi.PolicyControl) {
	configLock.Lock()
	defer configLock.Unlock()
	if len(policyControlConfig) == 0 {
		logger.PollConfigLog.Warnln("received empty Policy Control config. Clearing PCC Policy data")
		pccPolicies = make(map[SnssaiKey]*PccPolicy, 0)
		return
	}
	idGenerator := idgenerator.NewGenerator(1, math.MaxInt64)
	pccPolicies = make(map[SnssaiKey]*PccPolicy)
	for _, pc := range policyControlConfig {
		createPccPolicies(idGenerator, pc)
	}
	logger.PollConfigLog.Debugf("new PCC Policies: %+v", pccPolicies)
}

var createPccPolicies = func(idGenerator *idgenerator.IDGenerator, policyControlConfig nfConfigApi.PolicyControl) {
	if len(policyControlConfig.PccRules) == 0 {
		logger.PollConfigLog.Warnln("no PCC rules provided in PolicyControl config")
		return
	}
	snssai := models.Snssai{
		Sst: policyControlConfig.Snssai.Sst,
	}
	if sd, ok := policyControlConfig.Snssai.GetSdOk(); ok {
		snssai.Sd = sd
	}
	pccPolicy := makePccPolicy(idGenerator, snssai, policyControlConfig.PccRules)
	pccPolicies[SnssaiToKey(snssai)] = pccPolicy
}

func makePccPolicy(idGenerator *idgenerator.IDGenerator, snssai models.Snssai, pccRules []nfConfigApi.PccRule) (pccPolicy *PccPolicy) {
	pccPolicy = &PccPolicy{
		TraffContDecs: make(map[string]*models.TrafficControlData),
		QosDecs:       make(map[string]*models.QosData),
		PccRules:      make(map[string]*models.PccRule),
	}
	for _, pccrule := range pccRules {
		id, err := idGenerator.Allocate()
		if err != nil {
			logger.PollConfigLog.Errorf("idGenerator allocation failed: %v", err)
			continue
		}

		flowInfos, traffContDecs := makeFlowInfosAndTrafficContDesc(idGenerator, pccrule.Flows)
		refTcData := make([]string, 0, len(traffContDecs))
		for _, tcData := range traffContDecs {
			refTcData = append(refTcData, tcData.TcId)
			pccPolicy.TraffContDecs[tcData.TcId] = &tcData
		}

		warnIfGuaranteedRateIsUnenforceable(snssai, pccrule.RuleId, pccrule.Qos)
		qos := makeQosDesc(id, pccrule.Qos)
		if hasDefaultQosFlow(flowInfos) {
			qos.DefQosFlowIndication = openapi.PtrBool(true)
		}
		pccPolicy.QosDecs[qos.QosId] = &qos

		rule := models.NewPccRule(strconv.FormatInt(id, 10))
		if pccrule.Precedence != 0 {
			rule.SetPrecedence(pccrule.Precedence)
		}
		rule.SetFlowInfos(flowInfos)
		rule.SetRefTcData(refTcData)
		rule.SetRefQosData([]string{qos.QosId})
		pccPolicy.PccRules[pccrule.RuleId] = rule
	}
	return pccPolicy
}

func hasDefaultQosFlow(flows []models.FlowInformation) bool {
	for _, flow := range flows {
		desc := strings.TrimSpace(flow.GetFlowDescription())
		if strings.HasSuffix(desc, "any to assigned") {
			return true
		}
	}
	return false
}

// warnIfGuaranteedRateIsUnenforceable reports a guaranteed rate configured against a standardised
// Non-GBR 5QI, which is a misconfiguration the operator gets no other signal about: the rate is
// carried, the session is established, and nothing guarantees anything.
//
// Warned rather than dropped. Refusing the rate would discard configuration on the strength of a
// 5QI the operator may be about to correct, and the SMF decides whether to put a GBR IE on the QER
// by whether the rates are present, so dropping it here would quietly change what the user plane
// is programmed with rather than only what is logged.
//
// Only the standardised Non-GBR values are worth warning about. A value outside table 5.7.4-1 is
// dynamically assigned and carries its own QoS characteristics, which is how a guarantee has to be
// expressed over a link that no standardised GBR 5QI fits.
//
// It takes the rule id rather than the generated QoS id because the point is to name the rule the
// operator wrote, in the identifier they wrote it under — and the slice with it, because a rule id
// is only unique within one, so two slices can each hold a "rule1" and only one of them be wrong.
func warnIfGuaranteedRateIsUnenforceable(snssai models.Snssai, ruleID string, pccQos nfConfigApi.PccQos) {
	if !pcfContext.IsStandardisedNonGbr5QI(pccQos.FiveQi) {
		return
	}
	gbrUl, gbrDl := pccQos.GetGbrUl(), pccQos.GetGbrDl()
	if gbrUl == "" && gbrDl == "" {
		return
	}
	logger.PollConfigLog.Warnf(
		"PCC rule %q in slice %s configures a guaranteed bit rate (UL %q, DL %q) against 5QI %d, which TS 23.501 table 5.7.4-1 gives a Non-GBR resource type; the rate is carried as configured but nothing will guarantee it",
		ruleID, describeSnssai(snssai), gbrUl, gbrDl, pccQos.FiveQi)
}

// describeSnssai names a slice the way an operator configured it. The SD is optional in an
// S-NSSAI, so it is omitted rather than rendered empty when there is none.
func describeSnssai(snssai models.Snssai) string {
	if sd := snssai.GetSd(); sd != "" {
		return fmt.Sprintf("SST %d SD %s", snssai.GetSst(), sd)
	}
	return fmt.Sprintf("SST %d", snssai.GetSst())
}

func makeQosDesc(id int64, pccQos nfConfigApi.PccQos) models.QosData {
	qos := models.QosData{
		QosId: strconv.FormatInt(id, 10),
		Arp: &models.Arp{
			PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(pccQos.Arp.GetPriorityLevel())),
		},
	}
	if pccQos.FiveQi != 0 {
		qos.Var5qi = openapi.PtrInt32(pccQos.FiveQi)
	}
	if MaxbrUl, ok := pccQos.GetMaxBrUlOk(); ok {
		qos.MaxbrUl = *openapi.NewNullableString(MaxbrUl)
	}
	if MaxbrDl, ok := pccQos.GetMaxBrDlOk(); ok {
		qos.MaxbrDl = *openapi.NewNullableString(MaxbrDl)
	}
	if GbrUl, ok := pccQos.GetGbrUlOk(); ok {
		qos.GbrUl = *openapi.NewNullableString(GbrUl)
	}
	if GbrDl, ok := pccQos.GetGbrDlOk(); ok {
		qos.GbrDl = *openapi.NewNullableString(GbrDl)
	}
	switch pccQos.Arp.PreemptCap {
	case nfConfigApi.PREEMPTCAP_NOT_PREEMPT:
		qos.Arp.PreemptCap = models.PREEMPTIONCAPABILITY_NOT_PREEMPT
	case nfConfigApi.PREEMPTCAP_MAY_PREEMPT:
		qos.Arp.PreemptCap = models.PREEMPTIONCAPABILITY_MAY_PREEMPT
	}
	switch pccQos.Arp.PreemptVuln {
	case nfConfigApi.PREEMPTVULN_NOT_PREEMPTABLE:
		qos.Arp.PreemptVuln = models.PREEMPTIONVULNERABILITY_NOT_PREEMPTABLE
	case nfConfigApi.PREEMPTVULN_PREEMPTABLE:
		qos.Arp.PreemptVuln = models.PREEMPTIONVULNERABILITY_PREEMPTABLE
	}
	return qos
}

func makeFlowInfosAndTrafficContDesc(idGenerator *idgenerator.IDGenerator, pccFlows []nfConfigApi.PccFlow) ([]models.FlowInformation, []models.TrafficControlData) {
	parsedFlows := make([]models.FlowInformation, 0, len(pccFlows))
	parsedTrafficControl := make([]models.TrafficControlData, 0, len(pccFlows))

	for _, pccFlow := range pccFlows {
		id, err := idGenerator.Allocate()
		if err != nil {
			logger.PollConfigLog.Errorf("idGenerator allocation failed: %v", err)
			continue
		}

		var direction models.FlowDirectionRm
		switch pccFlow.Direction {
		case nfConfigApi.DIRECTION_DOWNLINK:
			direction = models.FLOWDIRECTIONRM_DOWNLINK
		case nfConfigApi.DIRECTION_UPLINK:
			direction = models.FLOWDIRECTIONRM_UPLINK
		case nfConfigApi.DIRECTION_BIDIRECTIONAL:
			direction = models.FLOWDIRECTIONRM_BIDIRECTIONAL
		case nfConfigApi.DIRECTION_UNSPECIFIED:
			direction = models.FLOWDIRECTIONRM_UNSPECIFIED
		default:
			direction = models.FLOWDIRECTIONRM_UNSPECIFIED
		}

		flow := models.FlowInformation{
			PackFiltId:      openapi.PtrString(strconv.FormatInt(id, 10)),
			FlowDescription: openapi.PtrString(pccFlow.GetDescription()),
			FlowDirection:   direction.Ptr(),
		}
		parsedFlows = append(parsedFlows, flow)

		var status models.FlowStatus
		switch pccFlow.Status {
		case nfConfigApi.STATUS_ENABLED:
			status = models.FLOWSTATUS_ENABLED
		case nfConfigApi.STATUS_DISABLED:
			status = models.FLOWSTATUS_DISABLED
		case nfConfigApi.STATUS_ENABLED_UPLINK:
			status = models.FLOWSTATUS_ENABLED_UPLINK
		case nfConfigApi.STATUS_ENABLED_DOWNLINK:
			status = models.FLOWSTATUS_ENABLED_DOWNLINK
		case nfConfigApi.STATUS_REMOVED:
			status = models.FLOWSTATUS_REMOVED
		}

		// traffic control info set based on flow at present
		tcData := models.TrafficControlData{
			TcId:       strconv.FormatInt(id, 10),
			FlowStatus: status.Ptr(),
		}
		parsedTrafficControl = append(parsedTrafficControl, tcData)
	}
	return parsedFlows, parsedTrafficControl
}

func (p PccPolicy) String() string {
	var s string

	s += "PccRules:\n"
	for name, rule := range p.PccRules {
		s += fmt.Sprintf("  PccRule[%v]: RuleId: %v, Precedence: %v\n", name, rule.PccRuleId, rule.Precedence)
		for i, refQos := range rule.RefQosData {
			s += fmt.Sprintf("    RefQosData[%v]: %s\n", i, refQos)
		}
		for i, refTc := range rule.RefTcData {
			s += fmt.Sprintf("    RefTcData[%v]: %s\n", i, refTc)
		}
		for i, flow := range rule.FlowInfos {
			s += fmt.Sprintf("    FlowInfo[%v]: FlowDesc: %v, TrafficClass: %v, FlowDir: %v\n", i, flow.FlowDescription, flow.TosTrafficClass, flow.FlowDirection)
		}
	}

	s += "QosDecs:\n"
	for name, qos := range p.QosDecs {
		s += fmt.Sprintf("  QosDec[%v]: QosId: %v, 5Qi: %v, MaxbrUl: %v, MaxbrDl: %v, GbrDl: %v, GbrUl: %v, PriorityLevel: %v\n",
			name, qos.QosId, qos.Var5qi, qos.MaxbrUl, qos.MaxbrDl, qos.GbrDl, qos.GbrUl, qos.PriorityLevel)
		if qos.Arp != nil {
			s += fmt.Sprintf("    Arp: PL: %v, PC: %v, PV: %v\n", qos.Arp.PriorityLevel, qos.Arp.PreemptCap, qos.Arp.PreemptVuln)
		}
	}

	s += "TrafficControlDecs:\n"
	for name, tr := range p.TraffContDecs {
		s += fmt.Sprintf("  TrafficDec[%v]: TcId: %v, FlowStatus: %v\n", name, tr.TcId, tr.FlowStatus)
	}

	return s
}
