// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"fmt"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/pcf/logger"
)

var MediaTypeTo5qiMap = map[models.MediaType]int32{
	models.MEDIATYPE_AUDIO:       1,
	models.MEDIATYPE_VIDEO:       2,
	models.MEDIATYPE_APPLICATION: 2,
	models.MEDIATYPE_DATA:        9,
	models.MEDIATYPE_CONTROL:     9,
	models.MEDIATYPE_TEXT:        9,
	models.MEDIATYPE_MESSAGE:     9,
	models.MEDIATYPE_OTHER:       9,
}

// getPccRuleId returns the PCC Rule ID as a plain numeric string.
func getPccRuleId(id int32) string {
	return fmt.Sprintf("%d", id)
}

// getQosId returns the QoS ID as a plain numeric string.
func getQosId(id int32) string {
	return fmt.Sprintf("%d", id)
}

// getTcId returns the Traffic Control ID as a plain numeric string.
func getTcId(id int32) string {
	return fmt.Sprintf("%d", id)
}

// GetChgId returns the charging ID in the format "ChgId-<id>".
func GetChgId(id int32) string {
	return fmt.Sprintf("ChgId-%d", id)
}

// GetUmId returns the Usage Monitoring ID for sponsored connectivity.
// Format: "umId-<aspId>-<sponId>".
func GetUmId(aspId, sponId string) string {
	return fmt.Sprintf("umId-%s-%s", aspId, sponId)
}

// GetPackFiltId returns the Packet filter Id as a plain numeric string.
func GetPackFiltId(id int32) string {
	return fmt.Sprintf("%d", id)
}

// CreatePccRule creates a PCC rule with the supplied ID, precedence, flow information, and application ID.
func CreatePccRule(id, precedence int32, flowInfo []models.FlowInformation, appID string) *models.PccRule {
	rule := models.NewPccRule(getPccRuleId(id))
	rule.SetAppId(appID)
	rule.SetFlowInfos(flowInfo)
	rule.SetPrecedence(precedence)
	return rule
}

func CreateQosData(id, var5qi, arpPriority int32) models.QosData {
	arp := models.NewArpWithDefaults()
	arp.SetPriorityLevel(arpPriority)
	arp.SetPreemptCap(models.PREEMPTIONCAPABILITY_NOT_PREEMPT)
	arp.SetPreemptVuln(models.PREEMPTIONVULNERABILITY_NOT_PREEMPTABLE)
	qosData := models.QosData{}
	qosData.SetQosId(getQosId(id))
	qosData.SetVar5qi(var5qi)
	qosData.SetArp(*arp)
	return qosData
}

func CreateTcData(id int32, fullID string, flowStatus models.FlowStatus) *models.TrafficControlData {
	if flowStatus == "" {
		flowStatus = models.FLOWSTATUS_ENABLED
	}
	if fullID == "" {
		fullID = getTcId(id)
	}
	trafficControlData := models.NewTrafficControlData(fullID)
	trafficControlData.SetFlowStatus(flowStatus)
	return trafficControlData
}

func CreateUmData(umId string, thresh models.UsageThreshold) models.UsageMonitoringData {
	usageMonitoringData := models.NewUsageMonitoringData(umId)
	if thresh.HasTotalVolume() {
		usageMonitoringData.SetVolumeThreshold(thresh.GetTotalVolume())
	}
	if thresh.HasUplinkVolume() {
		usageMonitoringData.SetVolumeThresholdUplink(thresh.GetUplinkVolume())
	}
	if thresh.HasDownlinkVolume() {
		usageMonitoringData.SetVolumeThresholdDownlink(thresh.GetDownlinkVolume())
	}
	if thresh.HasDuration() {
		usageMonitoringData.SetTimeThreshold(thresh.GetDuration())
	}
	return *usageMonitoringData
}

// Convert Packet Filter information list to Flow Information List(Packet Filter Usage always true),
// EthDescription is Not Supported
func ConvertPacketInfoToFlowInformation(infos []models.PacketFilterInfo) (flowInfos []models.FlowInformation) {
	for _, info := range infos {
		flowDirection, err := models.NewFlowDirectionRmFromValue(string(info.GetFlowDirection()))
		if err != nil {
			logger.UtilLog.Warnf("unsupported flow direction %q, defaulting to UNSPECIFIED", info.GetFlowDirection())
			flowDirection = models.FLOWDIRECTIONRM_UNSPECIFIED.Ptr()
		}

		flowInfo := models.NewFlowInformation()
		flowInfo.SetFlowDescription(info.GetPackFiltCont())
		flowInfo.SetPackFiltId(info.GetPackFiltId())
		flowInfo.SetPacketFilterUsage(true)
		flowInfo.SetTosTrafficClass(info.GetTosTrafficClass())
		flowInfo.SetSpi(info.GetSpi())
		flowInfo.SetFlowLabel(info.GetFlowLabel())
		flowInfo.SetFlowDirection(*flowDirection)

		flowInfos = append(flowInfos, *flowInfo)
	}
	return flowInfos
}

func GetPccRuleByAfAppId(pccRules map[string]models.PccRule, afAppId string) (string, models.PccRule, bool) {
	for key, pccRule := range pccRules {
		if pccRule.GetAppId() == afAppId {
			return key, pccRule, true
		}
	}
	return "", models.PccRule{}, false
}

func GetPccRuleByFlowInfos(pccRules map[string]models.PccRule, flowInfos []models.FlowInformation) (string, models.PccRule, bool) {
	found := false
	set := make(map[string]models.FlowInformation)

	for _, flowInfo := range flowInfos {
		set[flowInfo.GetFlowDescription()] = flowInfo
	}

	for key, pccRule := range pccRules {
		found = true
		for _, flowInfo := range pccRule.FlowInfos {
			if _, exists := set[flowInfo.GetFlowDescription()]; !exists {
				found = false
				break
			}
		}
		if found {
			return key, pccRule, true
		}
	}
	return "", models.PccRule{}, false
}

func SetPccRuleRelatedData(decicion *models.SmPolicyDecision, pccRule *models.PccRule,
	tcData *models.TrafficControlData, qosData *models.QosData, chgData *models.ChargingData,
	umData *models.UsageMonitoringData,
) {
	if tcData != nil {
		if decicion.TraffContDecs == nil {
			traffContDecs := make(map[string]models.TrafficControlData)
			decicion.TraffContDecs = &traffContDecs
		}
		(*decicion.TraffContDecs)[tcData.TcId] = *tcData
		pccRule.RefTcData = []string{tcData.TcId}
	}
	if qosData != nil {
		if decicion.QosDecs == nil {
			qosDecs := make(map[string]models.QosData)
			decicion.QosDecs = &qosDecs
		}
		(*decicion.QosDecs)[qosData.QosId] = *qosData
		pccRule.RefQosData = []string{qosData.QosId}
	}
	if chgData != nil {
		if decicion.ChgDecs == nil {
			decicion.ChgDecs = make(map[string]models.ChargingData)
		}
		decicion.ChgDecs[chgData.ChgId] = *chgData
		pccRule.RefChgData = []string{chgData.ChgId}
	}
	if umData != nil {
		if decicion.UmDecs == nil {
			decicion.UmDecs = make(map[string]models.UsageMonitoringData)
		}
		decicion.UmDecs[umData.UmId] = *umData
		pccRule.RefUmData = []string{umData.UmId}
	}
	if pccRule != nil {
		if decicion.PccRules == nil {
			decicion.PccRules = make(map[string]models.PccRule)
		}
		decicion.PccRules[pccRule.PccRuleId] = *pccRule
	}
}
