// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"fmt"

	"github.com/omec-project/openapi/v2"
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

// Get pcc rule Identity(PccRuleId-%d)
func GetPccRuleId(id int32) string {
	return fmt.Sprintf("PccRuleId-%d", id)
}

// Get qos Identity(QosId-%d)
func GetQosId(id int32) string {
	return fmt.Sprintf("QosId-%d", id)
}

// Get Traffic Control Identity(TcId-%d)
func GetTcId(id int32) string {
	return fmt.Sprintf("TcId-%d", id)
}

// Get Charging Identity(ChgId-%d)
func GetChgId(id int32) string {
	return fmt.Sprintf("ChgId-%d", id)
}

// Get Charging Identity(ChgId-%d)
func GetUmId(sponId, aspId string) string {
	return fmt.Sprintf("umId-%s-%s", sponId, aspId)
}

// Get Packet Filter Identity(PackFiltId-%d)
func GetPackFiltId(id int32) string {
	return fmt.Sprintf("PackFiltId-%d", id)
}

// Create Pcc Rule with param id, precedence, flow information, appID
func CreatePccRule(id, precedence int32, flowInfo []models.FlowInformation, appID string) *models.PccRule {
	rule := models.NewPccRule(GetPccRuleId(id))
	rule.SetAppId(appID)
	rule.SetFlowInfos(flowInfo)
	rule.SetPrecedence(precedence)
	return rule
}

func CreateQosData(id, var5qi, arp int32) models.QosData {
	return models.QosData{
		QosId:  GetQosId(id),
		Var5qi: openapi.PtrInt32(var5qi),
		Arp: &models.Arp{
			PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(arp)),
		},
	}
}

func CreateTcData(id int32, fullID string, flowStatus models.FlowStatus) *models.TrafficControlData {
	if flowStatus == "" {
		flowStatus = models.FLOWSTATUS_ENABLED
	}
	if fullID == "" {
		fullID = GetTcId(id)
	}
	return &models.TrafficControlData{
		TcId:       fullID,
		FlowStatus: flowStatus.Ptr(),
	}
}

func CreateUmData(umId string, thresh models.UsageThreshold) models.UsageMonitoringData {
	return models.UsageMonitoringData{
		UmId:                    umId,
		VolumeThreshold:         *openapi.NewNullableInt64(thresh.TotalVolume),
		VolumeThresholdUplink:   *openapi.NewNullableInt64(thresh.UplinkVolume),
		VolumeThresholdDownlink: *openapi.NewNullableInt64(thresh.DownlinkVolume),
		TimeThreshold:           *openapi.NewNullableInt32(thresh.Duration),
	}
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

		flowInfo := models.FlowInformation{
			FlowDescription:   info.PackFiltCont,
			PackFiltId:        info.PackFiltId,
			PacketFilterUsage: openapi.PtrBool(true),
			TosTrafficClass:   *openapi.NewNullableString(info.TosTrafficClass),
			Spi:               *openapi.NewNullableString(info.Spi),
			FlowLabel:         *openapi.NewNullableString(info.FlowLabel),
			FlowDirection:     flowDirection,
		}
		flowInfos = append(flowInfos, flowInfo)
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
