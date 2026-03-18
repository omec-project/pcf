// SPDX-FileCopyrightText: 2025 Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package producer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/omec-project/openapi"
	"github.com/omec-project/openapi/models"
	pcf_context "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/internal/notifyevent"
	"github.com/omec-project/pcf/logger"
	stats "github.com/omec-project/pcf/metrics"
	"github.com/omec-project/pcf/util"
	"github.com/omec-project/util/httpwrapper"
)

func transferAfRoutReqRmToAfRoutReq(AfRoutReqRm *models.AfRoutingRequirementRm) *models.AfRoutingRequirement {
	spVal := models.SpatialValidity{
		PresenceInfoList: AfRoutReqRm.SpVal.PresenceInfoList,
	}
	afRoutReq := models.AfRoutingRequirement{
		AppReloc:     AfRoutReqRm.AppReloc,
		RouteToLocs:  AfRoutReqRm.RouteToLocs,
		SpVal:        &spVal,
		TempVals:     AfRoutReqRm.TempVals,
		UpPathChgSub: AfRoutReqRm.UpPathChgSub,
	}
	return &afRoutReq
}

func transferMedCompRmToMedComp(medCompRm *models.MediaComponentRm) *models.MediaComponent {
	medSubComps := make(map[string]models.MediaSubComponent)
	for id, medSubCompRm := range medCompRm.MedSubComps {
		medSubComps[id] = models.MediaSubComponent(medSubCompRm)
	}
	medComp := models.MediaComponent{
		AfAppId:     medCompRm.AfAppId,
		AfRoutReq:   transferAfRoutReqRmToAfRoutReq(medCompRm.AfRoutReq),
		ContVer:     medCompRm.ContVer,
		Codecs:      medCompRm.Codecs,
		FStatus:     medCompRm.FStatus,
		MarBwDl:     medCompRm.MarBwDl,
		MarBwUl:     medCompRm.MarBwUl,
		MedCompN:    medCompRm.MedCompN,
		MedSubComps: medSubComps,
		MedType:     medCompRm.MedType,
		MirBwDl:     medCompRm.MirBwDl,
		MirBwUl:     medCompRm.MirBwUl,
		ResPrio:     medCompRm.ResPrio,
	}
	return &medComp
}

func handleMediaSubComponent(smPolicy *pcf_context.UeSmPolicyData, medComp *models.MediaComponent,
	medSubComp *models.MediaSubComponent, var5qi int32,
) (*models.PccRule, *models.ProblemDetails) {
	logger.PolicyAuthorizationlog.Debugf("Handling MediaSubComponent: FNum [%d], FStatus [%s]", medSubComp.FNum, medSubComp.FStatus)
	var flowInfos []models.FlowInformation
	var arp int32 = 1
	if tempFlowInfos, err := getFlowInfos(medSubComp); err != nil {
		logger.PolicyAuthorizationlog.Errorf("Failed to get FlowInfos for FNum [%d]: %v", medSubComp.FNum, err)
		problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
		return nil, &problemDetail
	} else {
		flowInfos = tempFlowInfos
		logger.PolicyAuthorizationlog.Debugf("Extracted %d FlowInfos for FNum [%d]", len(flowInfos), medSubComp.FNum)
	}

	pccRule := util.GetPccRuleByFlowInfos(smPolicy.PolicyDecision.PccRules, flowInfos)
	if pccRule == nil {
		logger.PolicyAuthorizationlog.Debugf("No existing PCC Rule found for FlowInfos. Creating new PCC Rule for FNum [%d]", medSubComp.FNum)

		maxPrecedence := getMaxPrecedence(smPolicy.PolicyDecision.PccRules)
		pccRule = util.CreatePccRule(smPolicy.PccRuleIdGenarator, maxPrecedence+1, nil, "")
		logger.PolicyAuthorizationlog.Debugf("Created new PCC Rule ID [%s]", pccRule.PccRuleId)

		// Create QoS Data
		qosData := util.CreateQosData(smPolicy.PccRuleIdGenarator, var5qi, arp)
		logger.PolicyAuthorizationlog.Debugf("Created QosData ID [%s] with Var5qi [%d]", qosData.QosId, var5qi)

		if var5qi <= 4 {
			var ul, dl bool
			qosData, ul, dl = updateQosInMedSubComp(&qosData, medComp, medSubComp)
			logger.PolicyAuthorizationlog.Debugf("Updated QoS Data (UL: %v, DL: %v)", ul, dl)

			if problemDetails := modifyRemainBitRate(smPolicy, &qosData, ul, dl); problemDetails != nil {
				logger.PolicyAuthorizationlog.Errorln("modifyRemainBitRate failed:", problemDetails.Detail)
				return nil, problemDetails
			}
		}

		// Assign PackFiltId to flows
		for i := range flowInfos {
			flowInfos[i].PackFiltId = util.GetPackFiltId(smPolicy.PackFiltIdGenarator)
			smPolicy.PackFiltMapToPccRuleId[flowInfos[i].PackFiltId] = pccRule.PccRuleId
			logger.PolicyAuthorizationlog.Infof("Assigned PackFiltId [%s] to PCC Rule ID [%s]", flowInfos[i].PackFiltId, pccRule.PccRuleId)
			smPolicy.PackFiltIdGenarator++
		}

		pccRule.FlowInfos = flowInfos

		// Create Traffic Control Data
		tcData := util.CreateTcData(smPolicy.PccRuleIdGenarator, "", medSubComp.FStatus)
		logger.PolicyAuthorizationlog.Debugf("Created TcData ID [%s] with FStatus [%s]", tcData.TcId, medSubComp.FStatus)

		// Set related data
		util.SetPccRuleRelatedData(smPolicy.PolicyDecision, pccRule, tcData, &qosData, nil, nil)
		logger.PolicyAuthorizationlog.Debugf("Set related data for PCC Rule ID [%s]", pccRule.PccRuleId)

		smPolicy.PccRuleIdGenarator++
	} else {
		logger.PolicyAuthorizationlog.Debugf("Found existing PCC Rule ID [%s] for FlowInfos", pccRule.PccRuleId)

		for _, qosID := range pccRule.RefQosData {
			qosData := *smPolicy.PolicyDecision.QosDecs[qosID]
			if qosData.Var5qi == var5qi && qosData.Var5qi <= 4 {
				var ul, dl bool
				qosData, ul, dl = updateQosInMedSubComp(smPolicy.PolicyDecision.QosDecs[qosID], medComp, medSubComp)
				logger.PolicyAuthorizationlog.Debugf("Updating existing QoS ID [%s] (UL: %v, DL: %v)", qosData.QosId, ul, dl)

				if problemDetails := modifyRemainBitRate(smPolicy, &qosData, ul, dl); problemDetails != nil {
					logger.PolicyAuthorizationlog.Errorf("modifyRemainBitRate failed for existing QoS ID [%s]: %s", qosData.QosId, problemDetails.Detail)
					return nil, problemDetails
				}
				smPolicy.PolicyDecision.QosDecs[qosData.QosId] = &qosData
			}
		}
	}

	// Final assignment
	smPolicy.PolicyDecision.PccRules[pccRule.PccRuleId] = pccRule
	logger.PolicyAuthorizationlog.Infof("PCC Rule ID [%s] stored successfully in PolicyDecision", pccRule.PccRuleId)

	return pccRule, nil
}

// HandlePostAppSessionsContext - Creates a new Individual Application Session Context resource
// Initial provisioning of service information (DONE)
// Gate control (DONE)
// Initial provisioning of sponsored connectivity information (DONE)
// Subscriptions to Service Data Flow QoS notification control (DONE)
// Subscription to Service Data Flow Deactivation (DONE)
// Initial provisioning of traffic routing information (DONE)
// Subscription to resources allocation outcome (DONE)
// Invocation of Multimedia Priority Services (TODO)
// Support of content versioning (TODO)
func HandlePostAppSessionsContext(request *httpwrapper.Request) *httpwrapper.Response {
	logger.PolicyAuthorizationlog.Debugln("handle Create AppSessions")

	appSessCtx := request.Body.(models.AppSessionContext)

	response, locationHeader, problemDetails := postAppSessCtxProcedure(&appSessCtx)

	if response != nil {
		headers := http.Header{
			"Location": {locationHeader},
		}
		stats.IncrementPcfPolicyAuthorizationStats("create", "application_sessions", "SUCCESS")
		return httpwrapper.NewResponse(http.StatusCreated, headers, response)
	} else if problemDetails != nil {
		stats.IncrementPcfPolicyAuthorizationStats("create", "application_sessions", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	stats.IncrementPcfPolicyAuthorizationStats("create", "events_subscription", "FAILURE")
	return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
}

func postAppSessCtxProcedure(appSessCtx *models.AppSessionContext) (*models.AppSessionContext,
	string, *models.ProblemDetails,
) {
	ascReqData := appSessCtx.AscReqData
	pcfSelf := pcf_context.PCF_Self()
	logger.PolicyAuthorizationlog.Infof("Received App Session Context Request: %+v", ascReqData)
	// Initial BDT policy indication(the only one which is not related to session)
	if ascReqData.BdtRefId != "" {
		logger.PolicyAuthorizationlog.Infof("Handling BDT Policy Indication for BdtRefId: %s", ascReqData.BdtRefId)
		if err := handleBDTPolicyInd(pcfSelf, appSessCtx); err != nil {
			problemDetail := util.GetProblemDetail(err.Error(), util.ERROR_REQUEST_PARAMETERS)
			logger.PolicyAuthorizationlog.Errorf("BDT Policy Indication failed: %v", err)
			return nil, "", &problemDetail
		}
		appSessID := fmt.Sprintf("BdtRefId-%s", ascReqData.BdtRefId)
		data := pcf_context.AppSessionData{
			AppSessionId:      appSessID,
			AppSessionContext: appSessCtx,
		}
		pcfSelf.AppSessionPool.Store(appSessID, &data)
		locationHeader := util.GetResourceUri(models.ServiceName_NPCF_POLICYAUTHORIZATION, appSessID)
		logger.PolicyAuthorizationlog.Infof("App Session Id[%s] Create", appSessID)
		return appSessCtx, locationHeader, nil
	}
	if ascReqData.UeIpv4 == "" && ascReqData.UeIpv6 == "" && ascReqData.UeMac == "" {
		logger.PolicyAuthorizationlog.Error("UE address identifiers are all empty (IPv4/IPv6/MAC)")
		problemDetail := util.GetProblemDetail("Ue UeIpv4 and UeIpv6 and UeMac are all empty", util.ERROR_REQUEST_PARAMETERS)
		return nil, "", &problemDetail
	}
	if ascReqData.AfRoutReq != nil && ascReqData.Dnn == "" {
		logger.PolicyAuthorizationlog.Error("DNN missing when AF Routing Requirement is provided")
		problemDetail := util.GetProblemDetail("DNN shall be present", util.ERROR_REQUEST_PARAMETERS)
		return nil, "", &problemDetail
	}
	var smPolicy *pcf_context.UeSmPolicyData
	if tempSmPolicy, err := pcfSelf.SessionBinding(ascReqData); err != nil {
		problemDetail := util.GetProblemDetail(fmt.Sprintf("Session Binding failed[%s]",
			err.Error()), util.PDU_SESSION_NOT_AVAILABLE)
		return nil, "", &problemDetail
	} else {
		smPolicy = tempSmPolicy
	}
	logger.PolicyAuthorizationlog.Infof("session Binding Success - UeIpv4[%s], UeIpv6[%s], UeMac[%s]",
		ascReqData.UeIpv4, ascReqData.UeIpv6, ascReqData.UeMac)
	ue := smPolicy.PcfUe
	updateSMpolicy := false

	var requestSuppFeat openapi.SupportedFeature
	if tempRequestSuppFeat, err := openapi.NewSupportedFeature(ascReqData.SuppFeat); err != nil {
		logger.PolicyAuthorizationlog.Errorln(err.Error())
	} else {
		requestSuppFeat = tempRequestSuppFeat
	}

	nSuppFeat := pcfSelf.PcfSuppFeats[models.ServiceName_NPCF_POLICYAUTHORIZATION].NegotiateWith(requestSuppFeat).String()
	// InfluenceOnTrafficRouting = 1 in 29514 &  Traffic Steering Control support = 1 in 29512
	traffRoutSupp := util.CheckSuppFeat(nSuppFeat, 1) && util.CheckSuppFeat(smPolicy.PolicyDecision.SuppFeat, 1)
	relatedPccRuleIds := make(map[string]string)
	logger.PolicyAuthorizationlog.Infof("Negotiated Supported Feature: %s", nSuppFeat)
	logger.PolicyAuthorizationlog.Infof("Traffic Routing Supported: %t", traffRoutSupp)
	if ascReqData.MedComponents != nil {
		// Handle Pcc rules
		var arp int32 = 1
		maxPrecedence := getMaxPrecedence(smPolicy.PolicyDecision.PccRules)
		for _, medComp := range ascReqData.MedComponents {
			logger.PolicyAuthorizationlog.Infof("Processing %d MediaComponents", len(ascReqData.MedComponents))
			var pccRule *models.PccRule
			var appID string
			var routeReq *models.AfRoutingRequirement
			// TODO: use specific algorithm instead of default, details in subsclause 7.3.3 of TS 29513
			var var5qi int32 = 9
			if medComp.MedType != "" {
				var5qi = util.MediaTypeTo5qiMap[medComp.MedType]
			}
			logger.PolicyAuthorizationlog.Infof("Processing Media Component[%d]: AppID=%s", medComp.MedCompN, appID)
			if medComp.MedSubComps != nil {
				logger.PolicyAuthorizationlog.Infof("Handling Media Component [%d] with %d sub-components", medComp.MedCompN, len(medComp.MedSubComps))
				var allFlowInfos []models.FlowInformation
				var medSubCompsList []models.MediaSubComponent
				for _, medSubComp := range medComp.MedSubComps {
					logger.PolicyAuthorizationlog.Infof("Extracting FlowInfos for FNum [%d]", medSubComp.FNum)

					if flowInfos, err := getFlowInfos(&medSubComp); err != nil {
						logger.PolicyAuthorizationlog.Errorf("Failed to get FlowInfos for FNum [%d]: %v", medSubComp.FNum, err)
						problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
						return nil, "", &problemDetail
					} else {
						allFlowInfos = append(allFlowInfos, flowInfos...)
						medSubCompsList = append(medSubCompsList, medSubComp)
					}
				}
				if tempPccRule, problemDetail := handleCombinedMediaSubComponents(smPolicy, &medComp, medSubCompsList, var5qi, allFlowInfos); problemDetail != nil {
					return nil, "", problemDetail
				} else {
					pccRule = tempPccRule
				}
				for _, medSubComp := range medSubCompsList {
					key := fmt.Sprintf("%d-%d", medComp.MedCompN, medSubComp.FNum)
					relatedPccRuleIds[key] = pccRule.PccRuleId
					logger.PolicyAuthorizationlog.Debugf("Mapped PCC Rule ID [%s] to MediaSubComp Key [%s]", pccRule.PccRuleId, key)
				}
				updateSMpolicy = true
				continue
			} else if medComp.AfAppId != "" {
				appID = medComp.AfAppId
				routeReq = medComp.AfRoutReq
				logger.PolicyAuthorizationlog.Debugf("Using AF App ID [%s] and RouteReq [%v] from Media Component [%d]", appID, routeReq, medComp.MedCompN)
			} else if ascReqData.AfAppId != "" {
				appID = ascReqData.AfAppId
				routeReq = ascReqData.AfRoutReq
				logger.PolicyAuthorizationlog.Debugf("Using AF App ID [%s] and RouteReq [%v] from AppSessionContext", appID, routeReq)
			} else {
				logger.PolicyAuthorizationlog.Warnf("Media Component [%d] lacks both sub-components and AfAppId", medComp.MedCompN)
				problemDetail := util.GetProblemDetail("Media Component needs flows of subComp or afAppId",
					util.REQUESTED_SERVICE_NOT_AUTHORIZED)
				return nil, "", &problemDetail
			}
			// Find pccRule by AfAppId, otherwise create a new pcc rule
			logger.PolicyAuthorizationlog.Debugf("AfAppId", appID)
			pccRule = util.GetPccRuleByAfAppId(smPolicy.PolicyDecision.PccRules, appID)
			if pccRule == nil {
				logger.PolicyAuthorizationlog.Infof("No existing PCC Rule found for AppID: %s, creating a new one", appID)
				pccRule = util.CreatePccRule(smPolicy.PccRuleIdGenarator, maxPrecedence+1, nil, appID)

				// Set QoS Data
				// TODO: use real ARP
				qosData := util.CreateQosData(smPolicy.PccRuleIdGenarator, var5qi, arp)
				logger.PolicyAuthorizationlog.Debugf("Created QoS Data with QosID: %s, 5QI: %d, ARP: %d", qosData.QosId, qosData.Var5qi, qosData.Arp.PriorityLevel)

				if var5qi <= 4 {
					// update QoS Data according to request BitRate
					var ul, dl bool
					qosData, ul, dl = updateQosInMedComp(qosData, &medComp)
					logger.PolicyAuthorizationlog.Debugf("Updated QoS Bitrate: QosID: %s, UL changed: %v, DL changed: %v", qosData.QosId, ul, dl)

					if problemDetails := modifyRemainBitRate(smPolicy, &qosData, ul, dl); problemDetails != nil {
						logger.PolicyAuthorizationlog.Errorf("Failed to modify remaining bitrate: %v", problemDetails)
						return nil, "", problemDetails
					}
				}
				util.SetPccRuleRelatedData(smPolicy.PolicyDecision, pccRule, nil, &qosData, nil, nil)
				logger.PolicyAuthorizationlog.Debugf("Set PCC Rule Related Data for RuleID: %s", pccRule.PccRuleId)

				smPolicy.PccRuleIdGenarator++
				maxPrecedence++
				logger.PolicyAuthorizationlog.Debugf("New PCC Rule created: RuleID: %s, AppID: %s, QosID: %s", pccRule.PccRuleId, appID, qosData.QosId)
			} else {
				logger.PolicyAuthorizationlog.Debugf("Found existing PCC Rule for AppID: %s, RuleID: %s", appID, pccRule.PccRuleId)

				// update pccRule's QoS
				for _, qosID := range pccRule.RefQosData {
					qosData := *smPolicy.PolicyDecision.QosDecs[qosID]
					logger.PolicyAuthorizationlog.Debugf("Evaluating existing QoS Data for update: QosID: %s, Var5QI: %d", qosData.QosId, qosData.Var5qi)

					if qosData.Var5qi == var5qi && qosData.Var5qi <= 4 {
						var ul, dl bool
						qosData, ul, dl = updateQosInMedComp(*smPolicy.PolicyDecision.QosDecs[qosID], &medComp)
						logger.PolicyAuthorizationlog.Infof("QoS Update check passed: QosID: %s, UL changed: %v, DL changed: %v", qosData.QosId, ul, dl)

						if problemDetails := modifyRemainBitRate(smPolicy, &qosData, ul, dl); problemDetails != nil {
							logger.PolicyAuthorizationlog.Errorf("Failed to modify remaining bitrate during QoS update: %v", problemDetails)
							return nil, "", problemDetails
						}
						smPolicy.PolicyDecision.QosDecs[qosData.QosId] = &qosData
						logger.PolicyAuthorizationlog.Debugf("QoS Data updated: QosID: %s", qosData.QosId)
					}
				}
			}
			// Initial provisioning of traffic routing information
			if traffRoutSupp {
				pccRule = provisioningOfTrafficRoutingInfo(smPolicy, appID, routeReq, medComp.FStatus)
			}
			key := fmt.Sprintf("%d", medComp.MedCompN)
			relatedPccRuleIds[key] = pccRule.PccRuleId
			updateSMpolicy = true
		}
	} else if ascReqData.AfAppId != "" {
		// Initial provisioning of traffic routing information
		if ascReqData.AfRoutReq != nil && traffRoutSupp {
			logger.PolicyAuthorizationlog.Infof("AF influence on Traffic Routing - AppId[%s]", ascReqData.AfAppId)
			pccRule := provisioningOfTrafficRoutingInfo(smPolicy, ascReqData.AfAppId, ascReqData.AfRoutReq, "")
			key := fmt.Sprintf("appID-%s", ascReqData.AfAppId)
			relatedPccRuleIds[key] = pccRule.PccRuleId
			updateSMpolicy = true
		} else {
			problemDetail := util.GetProblemDetail("Traffic routing not supported", util.REQUESTED_SERVICE_NOT_AUTHORIZED)
			return nil, "", &problemDetail
		}
	} else {
		problemDetail := util.GetProblemDetail("AF Request need AfAppId or Media Component to match Service Data Flow",
			util.ERROR_REQUEST_PARAMETERS)
		return nil, "", &problemDetail
	}

	// Event Subscription
	eventSubs := make(map[models.AfEvent]models.AfNotifMethod)
	if ascReqData.EvSubsc != nil {
		for _, subs := range ascReqData.EvSubsc.Events {
			if subs.NotifMethod == "" {
				// default value "EVENT_DETECTION"
				subs.NotifMethod = models.AfNotifMethod_EVENT_DETECTION
				logger.PolicyAuthorizationlog.Infof("AF Event [%v] missing NotifMethod, set default [%v]",
					subs.Event, subs.NotifMethod)
			}

			eventSubs[subs.Event] = subs.NotifMethod
			logger.PolicyAuthorizationlog.Infof("Subscribed AF Event [%v] with NotifMethod [%v]", subs.Event, subs.NotifMethod)

			var trig models.PolicyControlRequestTrigger
			switch subs.Event {
			case models.AfEvent_ACCESS_TYPE_CHANGE:
				trig = models.PolicyControlRequestTrigger_AC_TY_CH

			// case models.AfEvent_FAILED_RESOURCES_ALLOCATION:
			// 	trig = models.PolicyControlRequestTrigger_RES_RELEASE

			case models.AfEvent_PLMN_CHG:
				trig = models.PolicyControlRequestTrigger_PLMN_CH

			case models.AfEvent_QOS_NOTIF:
				// Subscriptions to Service Data Flow QoS notification control
				for _, pccRuleID := range relatedPccRuleIds {
					pccRule := smPolicy.PolicyDecision.PccRules[pccRuleID]
					for _, qosID := range pccRule.RefQosData {
						if qosData, ok := smPolicy.PolicyDecision.QosDecs[qosID]; ok {
							qosData.Qnc = true
							smPolicy.PolicyDecision.QosDecs[qosID] = qosData
						} else {
							logger.PolicyAuthorizationlog.Warnf("  QoS Data reference [%s] not found in PolicyDecision", qosID)
						}
					}
				}
				trig = models.PolicyControlRequestTrigger_QOS_NOTIF

			case models.AfEvent_SUCCESSFUL_RESOURCES_ALLOCATION:
				trig = models.PolicyControlRequestTrigger_SUCC_RES_ALLO

			case models.AfEvent_USAGE_REPORT:
				trig = models.PolicyControlRequestTrigger_US_RE

			default:
				logger.PolicyAuthorizationlog.Warnf("AF Event [%v] is unknown, skipping", subs.Event)
				continue
			}

			// Check and append trigger
			if !util.CheckPolicyControlReqTrig(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, trig) {
				smPolicy.PolicyDecision.PolicyCtrlReqTriggers = append(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, trig)
				updateSMpolicy = true
			} else {
				logger.PolicyAuthorizationlog.Infof("Trigger [%v] already exists, skipping add", trig)
			}
		}
	} else {
		logger.PolicyAuthorizationlog.Infof("No AF Event Subscriptions present in request")
	}
	filteredDecision := &models.SmPolicyDecision{
		PccRules:      make(map[string]*models.PccRule),
		QosDecs:       make(map[string]*models.QosData),
		TraffContDecs: make(map[string]*models.TrafficControlData),
	}
	for _, pccRuleID := range relatedPccRuleIds {
		if pccRule, ok := smPolicy.PolicyDecision.PccRules[pccRuleID]; ok {
			filteredDecision.PccRules[pccRuleID] = pccRule

			// include QoS data
			for _, qosID := range pccRule.RefQosData {
				if qos, ok := smPolicy.PolicyDecision.QosDecs[qosID]; ok {
					filteredDecision.QosDecs[qosID] = qos
				}
			}

			// include Traffic Control data
			for _, tcID := range pccRule.RefTcData {
				if tc, ok := smPolicy.PolicyDecision.TraffContDecs[tcID]; ok {
					filteredDecision.TraffContDecs[tcID] = tc
				}
			}
		}
	}
	// Initial provisioning of sponsored connectivity information
	if ascReqData.AspId != "" && ascReqData.SponId != "" {
		// SponsoredConnectivity = 2 in 29514 &  SponsoredConnectivity support = 12 in 29512
		logger.PolicyAuthorizationlog.Infof("Sponsored Connectivity Requested: AspId=%s, SponId=%s", ascReqData.AspId, ascReqData.SponId)
		supp := util.CheckSuppFeat(nSuppFeat, 2) && util.CheckSuppFeat(smPolicy.PolicyDecision.SuppFeat, 12)
		if !supp {
			problemDetail := util.GetProblemDetail("Sponsored Connectivity not supported", util.REQUESTED_SERVICE_NOT_AUTHORIZED)
			logger.PolicyAuthorizationlog.Errorln("Sponsored Connectivity not supported by UE or Policy Decision")
			return nil, "", &problemDetail
		}
		umID := util.GetUmId(ascReqData.AspId, ascReqData.SponId)
		var umData *models.UsageMonitoringData
		if tempUmData, err := extractUmData(umID, eventSubs, ascReqData.EvSubsc.UsgThres); err != nil {
			problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
			logger.PolicyAuthorizationlog.Errorf("Error extracting UsageMonitoringData: %v", err)
			return nil, "", &problemDetail
		} else {
			umData = tempUmData
		}
		if err := handleSponsoredConnectivityInformation(smPolicy, relatedPccRuleIds, ascReqData.AspId,
			ascReqData.SponId, ascReqData.SponStatus, umData, &updateSMpolicy); err != nil {
			problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
			logger.PolicyAuthorizationlog.Errorf("Failed to handle Sponsored Connectivity: %v", err)
			return nil, "", &problemDetail
		}
	}

	// Allocate App Session Id
	appSessID := ue.AllocUeAppSessionId(pcfSelf)
	appSessCtx.AscRespData = &models.AppSessionContextRespData{
		SuppFeat: nSuppFeat,
	}
	// Associate App Session to SMPolicy
	smPolicy.AppSessions[appSessID] = true
	data := pcf_context.AppSessionData{
		AppSessionId:      appSessID,
		AppSessionContext: appSessCtx,
		SmPolicyData:      smPolicy,
	}
	logger.PolicyAuthorizationlog.Infof("Created/updated AppSession with ID [%s]", appSessID)
	logger.PolicyAuthorizationlog.Infof("AppSession Context: %+v", appSessCtx)
	logger.PolicyAuthorizationlog.Infof("SM Policy associated with AppSession [%s]: %+v", appSessID, smPolicy)
	if len(relatedPccRuleIds) > 0 {
		data.RelatedPccRuleIds = relatedPccRuleIds
		data.PccRuleIdMapToCompId = reverseStringMap(relatedPccRuleIds)
		if relatedJSON, err := json.MarshalIndent(relatedPccRuleIds, "", "  "); err != nil {
			logger.PolicyAuthorizationlog.Errorf("Failed to marshal RelatedPccRuleIds: %v", err)
		} else {
			logger.PolicyAuthorizationlog.Debugf("RelatedPccRuleIds (pretty): %s", string(relatedJSON))
		}
		if reversedJSON, err := json.MarshalIndent(data.PccRuleIdMapToCompId, "", "  "); err != nil {
			logger.PolicyAuthorizationlog.Errorf("Failed to marshal PccRuleIdMapToCompId: %v", err)
		} else {
			logger.PolicyAuthorizationlog.Debugf("PccRuleIdMapToCompId (pretty): %s", string(reversedJSON))
		}
	}

	appSessCtx.EvsNotif = &models.EventsNotification{}
	// Set Event Subsciption related Data
	if len(eventSubs) > 0 {
		data.Events = eventSubs
		data.EventUri = ascReqData.EvSubsc.NotifUri
		logger.PolicyAuthorizationlog.Debugf("Registered Event Subscriptions for App Session ID: %s", appSessID)
		if _, exist := eventSubs[models.AfEvent_PLMN_CHG]; exist {
			afNotif := models.AfEventNotification{
				Event: models.AfEvent_PLMN_CHG,
			}
			appSessCtx.EvsNotif.EvNotifs = append(appSessCtx.EvsNotif.EvNotifs, afNotif)
			plmnID := smPolicy.PolicyContext.ServingNetwork
			if plmnID != nil {
				appSessCtx.EvsNotif.PlmnId = &models.PlmnId{
					Mcc: plmnID.Mcc,
					Mnc: plmnID.Mnc,
				}
			}
			logger.PolicyAuthorizationlog.Debugf("PLMN ID set in Event Notification: %s-%s", plmnID.Mcc, plmnID.Mnc)
		}
		if _, exist := eventSubs[models.AfEvent_ACCESS_TYPE_CHANGE]; exist {
			afNotif := models.AfEventNotification{
				Event: models.AfEvent_ACCESS_TYPE_CHANGE,
			}
			appSessCtx.EvsNotif.EvNotifs = append(appSessCtx.EvsNotif.EvNotifs, afNotif)
			appSessCtx.EvsNotif.AccessType = smPolicy.PolicyContext.AccessType
			appSessCtx.EvsNotif.RatType = smPolicy.PolicyContext.RatType
		}
		logger.PolicyAuthorizationlog.Debugf("AccessType and RatType set for ACCESS_TYPE_CHANGE")
	}
	if appSessCtx.EvsNotif.EvNotifs == nil {
		appSessCtx.EvsNotif = nil
		logger.PolicyAuthorizationlog.Debugln("No event notifications to include in App Session Context")
	}
	pcfSelf.AppSessionPool.Store(appSessID, &data)
	locationHeader := util.GetResourceUri(models.ServiceName_NPCF_POLICYAUTHORIZATION, appSessID)
	// Send Notification to SMF
	if updateSMpolicy {
		smPolicyID := fmt.Sprintf("%s-%d", ue.Supi, smPolicy.PolicyContext.PduSessionId)
		notification := models.SmPolicyNotification{
			ResourceUri:      util.GetResourceUri(models.ServiceName_NPCF_SMPOLICYCONTROL, smPolicyID),
			SmPolicyDecision: filteredDecision,
		}
		decisionJSON, err := json.MarshalIndent(filteredDecision, "", "  ")
		if err != nil {
			logger.PolicyAuthorizationlog.Errorf("Failed to marshal SmPolicyDecision: %+v", err)
		} else {
			logger.PolicyAuthorizationlog.Infof("SmPolicyDecision data: %s", string(decisionJSON))
		}
		notifyevent.DispatchSendSMPolicyUpdateNotifyEvent(smPolicy.PolicyContext.NotificationUri, &notification)
	}
	return appSessCtx, locationHeader, nil
}

func handleCombinedMediaSubComponents(
	smPolicy *pcf_context.UeSmPolicyData,
	medComp *models.MediaComponent,
	medSubComps []models.MediaSubComponent,
	var5qi int32,
	flowInfos []models.FlowInformation,
) (*models.PccRule, *models.ProblemDetails) {
	// Print all existing PCC Rule IDs before creating new ones
	for id, rule := range smPolicy.PolicyDecision.PccRules {
		logger.PolicyAuthorizationlog.Debugf("Existing PCC Rule ID: [%s]", id)

		// Print FlowDescriptions so you can identify IMS vs Internet
		for _, fi := range rule.FlowInfos {
			logger.PolicyAuthorizationlog.Debugf("  FlowDescription: %s", fi.FlowDescription)
		}

		// Print Qos IDs linked to this PCC Rule
		if len(rule.RefQosData) > 0 {
			for _, qosRef := range rule.RefQosData {
				qosData, ok := smPolicy.PolicyDecision.QosDecs[qosRef]
				if ok {
					logger.PolicyAuthorizationlog.Debugf("  QosData ID: [%s]", qosData.QosId)
				} else {
					logger.PolicyAuthorizationlog.Warnf("  QosData reference [%s] not found", qosRef)
				}
			}
		}
	}

	// Step 1: Try to find an existing PCC Rule that matches the given FlowInfos
	pccRule := util.GetPccRuleByFlowInfos(smPolicy.PolicyDecision.PccRules, flowInfos)

	// ----------------------------------------------------------------
	// Step 2: If no existing PCC Rule found, create a new one
	// ----------------------------------------------------------------
	if pccRule == nil {
		logger.PolicyAuthorizationlog.Infof("No existing PCC Rule found for combined FlowInfos. Creating new PCC Rule.")
		// Ensure PCC Rule ID generator is ahead of any existing PCC Rule ID
		maxExisting := getMaxPccRuleIdNum(smPolicy.PolicyDecision.PccRules)
		if smPolicy.PccRuleIdGenarator <= maxExisting {
			smPolicy.PccRuleIdGenarator = maxExisting + 1
		}
		// Determine max precedence among existing PCC Rules
		maxPrecedence := getMaxPrecedence(smPolicy.PolicyDecision.PccRules)
		// Create new PCC Rule (TS 29.214: QoS and PCC Rule handling)
		pccRule = util.CreatePccRule(smPolicy.PccRuleIdGenarator, maxPrecedence+1, nil, "")
		logger.PolicyAuthorizationlog.Infof("Created new PCC Rule ID [%s]", pccRule.PccRuleId)
		qosData := util.CreateQosData(smPolicy.PccRuleIdGenarator, var5qi, 8)
		logger.PolicyAuthorizationlog.Infof("Created QosData ID [%s] (5QI=%d)", qosData.QosId, var5qi)

		// If var5qi <= 4 (GBR flows), update QoS according to MediaSubComponents
		if var5qi <= 4 {
			var finalUL, finalDL bool
			for _, medSubComp := range medSubComps {
				var ul, dl bool
				qosData, ul, dl = updateQosInMedSubComp(&qosData, medComp, &medSubComp)
				finalUL = finalUL || ul
				finalDL = finalDL || dl
			}
			if problemDetails := modifyRemainBitRate(smPolicy, &qosData, finalUL, finalDL); problemDetails != nil {
				return nil, problemDetails
			}
		}

		// Assign Packet Filter IDs to FlowInfos and map them to PCC Rule
		for i := range flowInfos {
			flowInfos[i].PackFiltId = util.GetPackFiltId(smPolicy.PackFiltIdGenarator)
			smPolicy.PackFiltMapToPccRuleId[flowInfos[i].PackFiltId] = pccRule.PccRuleId
			smPolicy.PackFiltIdGenarator++
		}
		pccRule.FlowInfos = flowInfos
		tcData := util.CreateTcData(smPolicy.PccRuleIdGenarator, "", medSubComps[0].FStatus)
		util.SetPccRuleRelatedData(smPolicy.PolicyDecision, pccRule, tcData, &qosData, nil, nil)
		smPolicy.PccRuleIdGenarator++
		logger.PolicyAuthorizationlog.Debugf("PCC Rule ID [%s]", pccRule.PccRuleId)
	} else {
		// ----------------------------------------------------------------
		// Step 3 : Existing PCC Rule found, merge new flows and update if needed
		// ----------------------------------------------------------------
		logger.PolicyAuthorizationlog.Infof("Found existing PCC Rule ID [%s]", pccRule.PccRuleId)

		if len(pccRule.RefQosData) > 0 {
			for _, qosRef := range pccRule.RefQosData {
				qosData, ok := smPolicy.PolicyDecision.QosDecs[qosRef]
				if ok {
					logger.PolicyAuthorizationlog.Debugf("Existing PCC Rule [%s] has QosData ID [%s]",
						pccRule.PccRuleId, qosData.QosId)
				} else {
					logger.PolicyAuthorizationlog.Warnf("Existing PCC Rule [%s] has RefQosData [%s] but not found in QosDecs",
						pccRule.PccRuleId, qosRef)
				}
			}
		} else {
			logger.PolicyAuthorizationlog.Infof("Existing PCC Rule [%s] has no QosData references", pccRule.PccRuleId)
		}

		// Merge new flows (FlowInfos) into the existing PCC Rule if not already present
		for _, nf := range flowInfos {
			found := false
			for _, ef := range pccRule.FlowInfos {
				if ef.FlowDescription == nf.FlowDescription {
					found = true
					break
				}
			}
			if !found {
				nf.PackFiltId = util.GetPackFiltId(smPolicy.PackFiltIdGenarator)
				smPolicy.PackFiltMapToPccRuleId[nf.PackFiltId] = pccRule.PccRuleId
				smPolicy.PackFiltIdGenarator++
				pccRule.FlowInfos = append(pccRule.FlowInfos, nf)
			}
		}
	}

	smPolicy.PolicyDecision.PccRules[pccRule.PccRuleId] = pccRule
	logger.PolicyAuthorizationlog.Debugf("PCC Rule ID [%s] stored successfully in PolicyDecision", pccRule.PccRuleId)
	logger.PolicyAuthorizationlog.Debugf("Final PCC Rule Snapshot for ID [%s]:", pccRule.PccRuleId)
	logger.PolicyAuthorizationlog.Debugf("Precedence: %d", pccRule.Precedence)
	for _, fi := range pccRule.FlowInfos {
		logger.PolicyAuthorizationlog.Debugf("FlowDescription: %s, PackFiltId: %s", fi.FlowDescription, fi.PackFiltId)
	}
	logger.PolicyAuthorizationlog.Debugf("RefQosData:")
	for _, qosRef := range pccRule.RefQosData {
		qosData, ok := smPolicy.PolicyDecision.QosDecs[qosRef]
		if ok {
			logger.PolicyAuthorizationlog.Debugf("QosId: %s, 5QI: %d", qosData.QosId, qosData.Var5qi)
		} else {
			logger.PolicyAuthorizationlog.Warnf("    QosData reference [%s] not found", qosRef)
		}
	}
	pccRuleJSON, err := json.MarshalIndent(pccRule, "", "  ")
	if err != nil {
		logger.PolicyAuthorizationlog.Errorf("Failed to marshal PCC Rule [%s]: %+v", pccRule.PccRuleId, err)
	} else {
		logger.PolicyAuthorizationlog.Debugf("PCC Rule [%s] Full Snapshot:\n%s", pccRule.PccRuleId, string(pccRuleJSON))
	}
	return pccRule, nil
}

// HandleDeleteAppSession - Deletes an existing Individual Application Session Context
func HandleDeleteAppSessionContext(request *httpwrapper.Request) *httpwrapper.Response {
	eventsSubscReqData := request.Body.(*models.EventsSubscReqData)
	appSessID := request.Params["appSessionId"]
	logger.PolicyAuthorizationlog.Infof("handle Del AppSessions, AppSessionId[%s]", appSessID)

	problemDetails := DeleteAppSessionContextProcedure(appSessID, eventsSubscReqData)
	if problemDetails == nil {
		stats.IncrementPcfPolicyAuthorizationStats("delete", "application_sessions", "SUCCESS")
		return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
	} else {
		stats.IncrementPcfPolicyAuthorizationStats("delete", "application_sessions", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
}

func DeleteAppSessionContextProcedure(appSessID string,
	eventsSubscReqData *models.EventsSubscReqData,
) *models.ProblemDetails {
	pcfSelf := pcf_context.PCF_Self()
	var appSession *pcf_context.AppSessionData
	if val, ok := pcfSelf.AppSessionPool.Load(appSessID); ok {
		appSession = val.(*pcf_context.AppSessionData)
	}
	if appSession == nil {
		problemDetail := util.GetProblemDetail("can't find app session", util.APPLICATION_SESSION_CONTEXT_NOT_FOUND)
		return &problemDetail
	}
	if eventsSubscReqData != nil {
		logger.PolicyAuthorizationlog.Warnln("delete AppSessions does not support with Event Subscription")
	}
	// Remove related pcc rule resource
	smPolicy := appSession.SmPolicyData
	deletedSmPolicyDec := models.SmPolicyDecision{}
	for _, pccRuleID := range appSession.RelatedPccRuleIds {
		if err := smPolicy.RemovePccRule(pccRuleID, &deletedSmPolicyDec); err != nil {
			logger.PolicyAuthorizationlog.Warnln(err.Error())
		}
	}

	delete(smPolicy.AppSessions, appSessID)

	logger.PolicyAuthorizationlog.Infof("app session Id[%s] Del", appSessID)

	// TODO: AccUsageReport
	// if appSession.AccUsage != nil {

	// 	resp := models.AppSessionContext{
	// 		EvsNotif: &models.EventsNotification{
	// 			UsgRep: appSession.AccUsage,
	// 		},
	// 	}
	// 	message.SendHttpResponseMessage(httpChannel, nil, http.StatusOK, resp)
	// } else {
	// }

	pcfSelf.AppSessionPool.Delete(appSessID)

	smPolicy.ArrangeExistEventSubscription()

	// Notify SMF About Pcc Rule moval
	smPolicyID := fmt.Sprintf("%s-%d", smPolicy.PcfUe.Supi, smPolicy.PolicyContext.PduSessionId)
	notification := models.SmPolicyNotification{
		ResourceUri:      util.GetResourceUri(models.ServiceName_NPCF_SMPOLICYCONTROL, smPolicyID),
		SmPolicyDecision: &deletedSmPolicyDec,
	}
	notifyevent.DispatchSendSMPolicyUpdateNotifyEvent(smPolicy.PolicyContext.NotificationUri, &notification)
	logger.PolicyAuthorizationlog.Debugf("send SM Policy[%s] Update Notification", smPolicyID)
	return nil
}

// HandleGetAppSession - Reads an existing Individual Application Session Context
func HandleGetAppSessionContext(request *httpwrapper.Request) *httpwrapper.Response {
	appSessID := request.Params["appSessionId"]
	logger.PolicyAuthorizationlog.Infof("handle Get AppSessions, AppSessionId[%s]", appSessID)

	problemDetails, response := GetAppSessionContextProcedure(appSessID)
	if problemDetails == nil {
		stats.IncrementPcfPolicyAuthorizationStats("get", "application_sessions", "SUCCESS")
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else {
		stats.IncrementPcfPolicyAuthorizationStats("get", "application_sessions", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
}

func GetAppSessionContextProcedure(appSessID string) (*models.ProblemDetails, *models.AppSessionContext) {
	pcfSelf := pcf_context.PCF_Self()

	var appSession *pcf_context.AppSessionData
	if val, ok := pcfSelf.AppSessionPool.Load(appSessID); ok {
		appSession = val.(*pcf_context.AppSessionData)
	}
	if appSession == nil {
		problemDetail := util.GetProblemDetail("can't find app session", util.APPLICATION_SESSION_CONTEXT_NOT_FOUND)
		return &problemDetail, nil
	}
	logger.PolicyAuthorizationlog.Debugf("app Session Id[%s] Get", appSessID)
	return nil, appSession.AppSessionContext
}

// HandleModAppSession - Modifies an existing Individual Application Session Context
func HandleModAppSessionContext(request *httpwrapper.Request) *httpwrapper.Response {
	appSessID := request.Params["appSessionId"]
	ascUpdateData := request.Body.(models.AppSessionContextUpdateData)
	logger.PolicyAuthorizationlog.Infof("handle Modify AppSessions, AppSessionId[%s]", appSessID)

	problemDetails, response := ModAppSessionContextProcedure(appSessID, ascUpdateData)
	if problemDetails == nil {
		stats.IncrementPcfPolicyAuthorizationStats("update", "application_sessions", "SUCCESS")
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else {
		stats.IncrementPcfPolicyAuthorizationStats("update", "application_sessions", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
}

func ModAppSessionContextProcedure(appSessID string,
	ascUpdateData models.AppSessionContextUpdateData,
) (*models.ProblemDetails, *models.AppSessionContext) {
	pcfSelf := pcf_context.PCF_Self()
	var appSession *pcf_context.AppSessionData
	if val, ok := pcfSelf.AppSessionPool.Load(appSessID); ok {
		appSession = val.(*pcf_context.AppSessionData)
	}
	if appSession == nil {
		problemDetail := util.GetProblemDetail("can't find app session", util.APPLICATION_SESSION_CONTEXT_NOT_FOUND)
		return &problemDetail, nil
	}
	appSessCtx := appSession.AppSessionContext
	if ascUpdateData.BdtRefId != "" {
		appSessCtx.AscReqData.BdtRefId = ascUpdateData.BdtRefId
		if err := handleBDTPolicyInd(pcfSelf, appSessCtx); err != nil {
			problemDetail := util.GetProblemDetail(err.Error(), util.ERROR_REQUEST_PARAMETERS)
			return &problemDetail, nil
		}
		logger.PolicyAuthorizationlog.Debugf("app session Id[%s] Updated", appSessID)
		return nil, appSessCtx
	}
	smPolicy := appSession.SmPolicyData
	if smPolicy == nil {
		problemDetail := util.GetProblemDetail("Can't find related PDU Session", util.REQUESTED_SERVICE_NOT_AUTHORIZED)
		return &problemDetail, nil
	}
	// InfluenceOnTrafficRouting = 1 in 29514 &  Traffic Steering Control support = 1 in 29512
	traffRoutSupp := util.CheckSuppFeat(appSessCtx.AscRespData.SuppFeat,
		1) && util.CheckSuppFeat(smPolicy.PolicyDecision.SuppFeat, 1)
	relatedPccRuleIds := make(map[string]string)
	// Event Subscription
	eventSubs := make(map[models.AfEvent]models.AfNotifMethod)
	updateSMpolicy := false

	if ascUpdateData.MedComponents != nil {
		maxPrecedence := getMaxPrecedence(smPolicy.PolicyDecision.PccRules)
		for compN, medCompRm := range ascUpdateData.MedComponents {
			medComp := transferMedCompRmToMedComp(&medCompRm)
			removeMediaComp(appSession, compN)
			if reflect.ValueOf(medComp).IsZero() {
				// remove MediaComp(media Comp is null)
				continue
			}
			// modify MediaComp(remove and reinstall again)
			var pccRule *models.PccRule
			var appID string
			var routeReq *models.AfRoutingRequirement
			// TODO: use specific algorithm instead of default, details in subsclause 7.3.3 of TS 29513
			var var5qi int32 = 9
			if medComp.MedType != "" {
				var5qi = util.MediaTypeTo5qiMap[medComp.MedType]
			}
			if medComp.MedSubComps != nil {
				for _, medSubComp := range medComp.MedSubComps {
					if tempPccRule, problemDetail := handleMediaSubComponent(smPolicy, medComp,
						&medSubComp, var5qi); problemDetail != nil {
						return problemDetail, nil
					} else {
						pccRule = tempPccRule
					}
					key := fmt.Sprintf("%d-%d", medComp.MedCompN, medSubComp.FNum)
					relatedPccRuleIds[key] = pccRule.PccRuleId
					updateSMpolicy = true
				}
				continue
			} else if medComp.AfAppId != "" {
				// if medComp.AfAppId has value -> find pccRule by reqData.AfAppId, otherwise create a new pcc rule
				appID = medComp.AfAppId
				routeReq = medComp.AfRoutReq
			} else if ascUpdateData.AfAppId != "" {
				appID = ascUpdateData.AfAppId
				routeReq = medComp.AfRoutReq
			} else {
				problemDetail := util.GetProblemDetail("Media Component needs flows of subComp or afAppId",
					util.REQUESTED_SERVICE_NOT_AUTHORIZED)
				return &problemDetail, nil
			}

			pccRule = util.GetPccRuleByAfAppId(smPolicy.PolicyDecision.PccRules, appID)
			if pccRule == nil { // create new pcc rule
				pccRule = util.CreatePccRule(smPolicy.PccRuleIdGenarator, maxPrecedence+1, nil, appID)
				// Set QoS Data
				// TODO: use real arp
				qosData := util.CreateQosData(smPolicy.PccRuleIdGenarator, var5qi, 8)
				if var5qi <= 4 {
					// update Qos Data according to request BitRate
					var ul, dl bool
					qosData, ul, dl = updateQosInMedComp(qosData, medComp)
					if problemDetail := modifyRemainBitRate(smPolicy, &qosData, ul, dl); problemDetail != nil {
						return problemDetail, nil
					}
				}
				util.SetPccRuleRelatedData(smPolicy.PolicyDecision, pccRule, nil, &qosData, nil, nil)
				smPolicy.PccRuleIdGenarator++
				maxPrecedence++
			} else {
				// update qos
				var qosData models.QosData
				for _, qosID := range pccRule.RefQosData {
					qosData = *smPolicy.PolicyDecision.QosDecs[qosID]
					if qosData.Var5qi == var5qi && qosData.Var5qi <= 4 {
						var ul, dl bool
						qosData, ul, dl = updateQosInMedComp(*smPolicy.PolicyDecision.QosDecs[qosID], medComp)
						if problemDetail := modifyRemainBitRate(smPolicy, &qosData, ul, dl); problemDetail != nil {
							return problemDetail, nil
						}
						smPolicy.PolicyDecision.QosDecs[qosData.QosId] = &qosData
					}
				}
			}
			// Modify provisioning of traffic routing information
			if traffRoutSupp {
				pccRule = provisioningOfTrafficRoutingInfo(smPolicy, appID, routeReq, medComp.FStatus)
			}
			key := fmt.Sprintf("%d", medComp.MedCompN)
			relatedPccRuleIds[key] = pccRule.PccRuleId
			updateSMpolicy = true
		}
	}

	// Update of traffic routing information
	// TODO: check ascUpdateData.AfAppId with appSessCtx.AscReqData.AfAppId (now ascUpdateData.AfAppId is empty)
	if ascUpdateData.AfRoutReq != nil && traffRoutSupp {
		logger.PolicyAuthorizationlog.Infof("update traffic routing info - [%+v]", ascUpdateData.AfRoutReq)
		appSessCtx.AscReqData.AfRoutReq = transferAfRoutReqRmToAfRoutReq(ascUpdateData.AfRoutReq)
		// Update SmPolicyDecision
		pccRule := provisioningOfTrafficRoutingInfo(smPolicy,
			appSessCtx.AscReqData.AfAppId, appSessCtx.AscReqData.AfRoutReq, "")
		key := fmt.Sprintf("appID-%s", appSessCtx.AscReqData.AfAppId)
		relatedPccRuleIds[key] = pccRule.PccRuleId
		updateSMpolicy = true
	}

	// Merge Original PccRuleId and new
	for key, pccRuleID := range appSession.RelatedPccRuleIds {
		relatedPccRuleIds[key] = pccRuleID
	}

	if ascUpdateData.EvSubsc != nil {
		for _, subs := range ascUpdateData.EvSubsc.Events {
			if subs.NotifMethod == "" {
				// default value "EVENT_DETECTION"
				subs.NotifMethod = models.AfNotifMethod_EVENT_DETECTION
			}
			eventSubs[subs.Event] = subs.NotifMethod
			var trig models.PolicyControlRequestTrigger
			switch subs.Event {
			case models.AfEvent_ACCESS_TYPE_CHANGE:
				trig = models.PolicyControlRequestTrigger_AC_TY_CH
			// case models.AfEvent_FAILED_RESOURCES_ALLOCATION:
			// 	// Subscription to Service Data Flow Deactivation
			// 	trig = models.PolicyControlRequestTrigger_SUCC_RES_ALLO
			case models.AfEvent_PLMN_CHG:
				trig = models.PolicyControlRequestTrigger_PLMN_CH
			case models.AfEvent_QOS_NOTIF:
				// Subscriptions to Service Data Flow QoS notification control
				for _, pccRuleID := range relatedPccRuleIds {
					pccRule := smPolicy.PolicyDecision.PccRules[pccRuleID]
					for _, qosID := range pccRule.RefQosData {
						qosData := smPolicy.PolicyDecision.QosDecs[qosID]
						qosData.Qnc = true
						smPolicy.PolicyDecision.QosDecs[qosID] = qosData
					}
				}
				trig = models.PolicyControlRequestTrigger_QOS_NOTIF
			case models.AfEvent_SUCCESSFUL_RESOURCES_ALLOCATION:
				// Subscription to resources allocation outcome
				trig = models.PolicyControlRequestTrigger_SUCC_RES_ALLO
			case models.AfEvent_USAGE_REPORT:
				trig = models.PolicyControlRequestTrigger_US_RE
			default:
				logger.PolicyAuthorizationlog.Warnln("AF Event is unknown")
				continue
			}
			if !util.CheckPolicyControlReqTrig(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, trig) {
				smPolicy.PolicyDecision.PolicyCtrlReqTriggers = append(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, trig)
				updateSMpolicy = true
			}
		}
		// update Context
		if appSessCtx.AscReqData.EvSubsc == nil {
			appSessCtx.AscReqData.EvSubsc = new(models.EventsSubscReqData)
		}
		appSessCtx.AscReqData.EvSubsc.Events = ascUpdateData.EvSubsc.Events
		if ascUpdateData.EvSubsc.NotifUri != "" {
			appSessCtx.AscReqData.EvSubsc.NotifUri = ascUpdateData.EvSubsc.NotifUri
			appSession.EventUri = ascUpdateData.EvSubsc.NotifUri
		}
		if ascUpdateData.EvSubsc.UsgThres != nil {
			appSessCtx.AscReqData.EvSubsc.UsgThres = threshRmToThresh(ascUpdateData.EvSubsc.UsgThres)
		}
	} else {
		// remove eventSubs
		appSession.Events = nil
		appSession.EventUri = ""
		appSessCtx.AscReqData.EvSubsc = nil
	}

	// Moification provisioning of sponsored connectivity information
	if ascUpdateData.AspId != "" && ascUpdateData.SponId != "" {
		umID := util.GetUmId(ascUpdateData.AspId, ascUpdateData.SponId)
		var umData *models.UsageMonitoringData
		if tempUmData, err := extractUmData(umID, eventSubs,
			threshRmToThresh(ascUpdateData.EvSubsc.UsgThres)); err != nil {
			problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
			return &problemDetail, nil
		} else {
			umData = tempUmData
		}
		if err := handleSponsoredConnectivityInformation(smPolicy, relatedPccRuleIds, ascUpdateData.AspId,
			ascUpdateData.SponId, ascUpdateData.SponStatus, umData, &updateSMpolicy); err != nil {
			problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
			return &problemDetail, nil
		}
	}

	if len(relatedPccRuleIds) > 0 {
		appSession.RelatedPccRuleIds = relatedPccRuleIds
		appSession.PccRuleIdMapToCompId = reverseStringMap(relatedPccRuleIds)
	}
	appSessCtx.EvsNotif = &models.EventsNotification{}
	// Set Event Subsciption related Data
	if len(eventSubs) > 0 {
		appSession.Events = eventSubs
		if _, exist := eventSubs[models.AfEvent_PLMN_CHG]; exist {
			afNotif := models.AfEventNotification{
				Event: models.AfEvent_PLMN_CHG,
			}
			appSessCtx.EvsNotif.EvNotifs = append(appSessCtx.EvsNotif.EvNotifs, afNotif)
			plmnID := smPolicy.PolicyContext.ServingNetwork
			if plmnID != nil {
				appSessCtx.EvsNotif.PlmnId = &models.PlmnId{
					Mcc: plmnID.Mcc,
					Mnc: plmnID.Mnc,
				}
			}
		}
		if _, exist := eventSubs[models.AfEvent_ACCESS_TYPE_CHANGE]; exist {
			afNotif := models.AfEventNotification{
				Event: models.AfEvent_ACCESS_TYPE_CHANGE,
			}
			appSessCtx.EvsNotif.EvNotifs = append(appSessCtx.EvsNotif.EvNotifs, afNotif)
			appSessCtx.EvsNotif.AccessType = smPolicy.PolicyContext.AccessType
			appSessCtx.EvsNotif.RatType = smPolicy.PolicyContext.RatType
		}
	}
	if appSessCtx.EvsNotif.EvNotifs == nil {
		appSessCtx.EvsNotif = nil
	}

	// TODO: MPS Service
	logger.PolicyAuthorizationlog.Debugf("app session Id[%s] Updated", appSessID)

	smPolicy.ArrangeExistEventSubscription()

	// Send Notification to SMF
	if updateSMpolicy {
		smPolicyID := fmt.Sprintf("%s-%d", smPolicy.PcfUe.Supi, smPolicy.PolicyContext.PduSessionId)
		notification := models.SmPolicyNotification{
			ResourceUri:      util.GetResourceUri(models.ServiceName_NPCF_SMPOLICYCONTROL, smPolicyID),
			SmPolicyDecision: smPolicy.PolicyDecision,
		}
		notifyevent.DispatchSendSMPolicyUpdateNotifyEvent(smPolicy.PolicyContext.NotificationUri, &notification)
		logger.PolicyAuthorizationlog.Debugf("send SM Policy[%s] Update Notification", smPolicyID)
	}
	return nil, appSessCtx
}

// HandleDeleteEventsSubsc - deletes the Events Subscription subresource
func HandleDeleteEventsSubscContext(request *httpwrapper.Request) *httpwrapper.Response {
	appSessID := request.Params["appSessID"]
	logger.PolicyAuthorizationlog.Debugf("handle Del AppSessions Events Subsc, AppSessionId[%s]", appSessID)

	problemDetails := DeleteEventsSubscContextProcedure(appSessID)
	if problemDetails == nil {
		stats.IncrementPcfPolicyAuthorizationStats("delete", "events_subscriptions", "SUCCESS")
		return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
	} else {
		stats.IncrementPcfPolicyAuthorizationStats("delete", "events_subscriptions", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
}

func DeleteEventsSubscContextProcedure(appSessID string) *models.ProblemDetails {
	pcfSelf := pcf_context.PCF_Self()
	var appSession *pcf_context.AppSessionData
	if val, ok := pcfSelf.AppSessionPool.Load(appSessID); ok {
		appSession = val.(*pcf_context.AppSessionData)
	}
	if appSession == nil {
		problemDetail := util.GetProblemDetail("can't find app session", util.APPLICATION_SESSION_CONTEXT_NOT_FOUND)
		return &problemDetail
	}
	appSession.Events = nil
	appSession.EventUri = ""
	appSession.AppSessionContext.EvsNotif = nil
	appSession.AppSessionContext.AscReqData.EvSubsc = nil

	// changed := appSession.SmPolicyData.ArrangeExistEventSubscription()

	logger.PolicyAuthorizationlog.Debugf("app session Id[%s] Del Events Subsc success", appSessID)

	smPolicy := appSession.SmPolicyData
	// Send Notification to SMF
	if changed := appSession.SmPolicyData.ArrangeExistEventSubscription(); changed {
		smPolicyID := fmt.Sprintf("%s-%d", smPolicy.PcfUe.Supi, smPolicy.PolicyContext.PduSessionId)
		notification := models.SmPolicyNotification{
			ResourceUri:      util.GetResourceUri(models.ServiceName_NPCF_SMPOLICYCONTROL, smPolicyID),
			SmPolicyDecision: smPolicy.PolicyDecision,
		}
		notifyevent.DispatchSendSMPolicyUpdateNotifyEvent(smPolicy.PolicyContext.NotificationUri, &notification)
		logger.PolicyAuthorizationlog.Debugf("send SM Policy[%s] Update Notification", smPolicyID)
	}
	return nil
}

// HandleUpdateEventsSubsc - creates or modifies an Events Subscription subresource
func HandleUpdateEventsSubscContext(request *httpwrapper.Request) *httpwrapper.Response {
	EventsSubscReqData := request.Body.(models.EventsSubscReqData)
	appSessID := request.Params["appSessID"]
	logger.PolicyAuthorizationlog.Debugf("handle Put AppSessions Events Subsc, AppSessionId[%s]", appSessID)

	response, locationHeader, status, problemDetails := UpdateEventsSubscContextProcedure(appSessID, EventsSubscReqData)
	if problemDetails != nil {
		stats.IncrementPcfPolicyAuthorizationStats("update", "events_subscriptions", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else if status == http.StatusCreated {
		stats.IncrementPcfPolicyAuthorizationStats("update", "events_subscriptions", "SUCCESS")
		headers := http.Header{
			"Location": {locationHeader},
		}
		return httpwrapper.NewResponse(http.StatusCreated, headers, response)
	} else if status == http.StatusOK {
		stats.IncrementPcfPolicyAuthorizationStats("update", "events_subscriptions", "SUCCESS")
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if status == http.StatusNoContent {
		stats.IncrementPcfPolicyAuthorizationStats("update", "events_subscriptions", "SUCCESS")
		return httpwrapper.NewResponse(http.StatusNoContent, nil, response)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	stats.IncrementPcfPolicyAuthorizationStats("update", "events_subscriptions", "FAILURE")
	return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
}

func SendAppSessionEventNotification(appSession *pcf_context.AppSessionData, request models.EventsNotification) {
	logger.PolicyAuthorizationlog.Debugln("send App Session Event Notification")
	if appSession == nil {
		logger.PolicyAuthorizationlog.Warnln("send App Session Event Notification Error[appSession is nil]")
		return
	}
	uri := appSession.EventUri
	if uri != "" {
		request.EvSubsUri = fmt.Sprintf("%s/events-subscription",
			util.GetResourceUri(models.ServiceName_NPCF_POLICYAUTHORIZATION, appSession.AppSessionId))
		client := util.GetNpcfPolicyAuthorizationCallbackClient()
		httpResponse, err := client.PolicyAuthorizationEventNotificationApi.PolicyAuthorizationEventNotification(
			context.Background(), uri, request)
		if err != nil {
			if httpResponse != nil {
				logger.PolicyAuthorizationlog.Warnf("send App Session Event Notification Error[%s]", httpResponse.Status)
			} else {
				logger.PolicyAuthorizationlog.Warnf("send App Session Event Notification Failed[%s]", err.Error())
			}
			return
		} else if httpResponse == nil {
			logger.PolicyAuthorizationlog.Warnln("send App Session Event Notification Failed[HTTP Response is nil]")
			return
		}
		defer func() {
			if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
				logger.PolicyAuthorizationlog.Errorf(
					"PolicyAuthorizationEventNotification response body cannot close: %+v",
					rspCloseErr)
			}
		}()
		if httpResponse.StatusCode != http.StatusOK && httpResponse.StatusCode != http.StatusNoContent {
			logger.PolicyAuthorizationlog.Warnln("send App Session Event Notification Failed")
		} else {
			logger.PolicyAuthorizationlog.Debugln("send App Session Event Notification Success")
		}
	}
}

func UpdateEventsSubscContextProcedure(appSessID string, eventsSubscReqData models.EventsSubscReqData) (
	*models.UpdateEventsSubscResponse, string, int, *models.ProblemDetails,
) {
	pcfSelf := pcf_context.PCF_Self()

	var appSession *pcf_context.AppSessionData
	if val, ok := pcfSelf.AppSessionPool.Load(appSessID); ok {
		appSession = val.(*pcf_context.AppSessionData)
	}
	if appSession == nil {
		problemDetail := util.GetProblemDetail("can't find app session", util.APPLICATION_SESSION_CONTEXT_NOT_FOUND)
		return nil, "", int(problemDetail.Status), &problemDetail
	}
	smPolicy := appSession.SmPolicyData
	eventSubs := make(map[models.AfEvent]models.AfNotifMethod)

	updataSmPolicy := false
	created := appSession.Events == nil

	for _, subs := range eventsSubscReqData.Events {
		if subs.NotifMethod == "" {
			// default value "EVENT_DETECTION"
			subs.NotifMethod = models.AfNotifMethod_EVENT_DETECTION
		}
		eventSubs[subs.Event] = subs.NotifMethod
		var trig models.PolicyControlRequestTrigger
		switch subs.Event {
		case models.AfEvent_ACCESS_TYPE_CHANGE:
			trig = models.PolicyControlRequestTrigger_AC_TY_CH
		// case models.AfEvent_FAILED_RESOURCES_ALLOCATION:
		// 	// Subscription to Service Data Flow Deactivation
		// 	trig = models.PolicyControlRequestTrigger_SUCC_RES_ALLO
		case models.AfEvent_PLMN_CHG:
			trig = models.PolicyControlRequestTrigger_PLMN_CH
		case models.AfEvent_QOS_NOTIF:
			// Subscriptions to Service Data Flow QoS notification control
			for _, pccRuleID := range appSession.RelatedPccRuleIds {
				pccRule := smPolicy.PolicyDecision.PccRules[pccRuleID]
				for _, qosID := range pccRule.RefQosData {
					qosData := smPolicy.PolicyDecision.QosDecs[qosID]
					qosData.Qnc = true
					smPolicy.PolicyDecision.QosDecs[qosID] = qosData
				}
			}
			trig = models.PolicyControlRequestTrigger_QOS_NOTIF
		case models.AfEvent_SUCCESSFUL_RESOURCES_ALLOCATION:
			// Subscription to resources allocation outcome
			trig = models.PolicyControlRequestTrigger_SUCC_RES_ALLO
		case models.AfEvent_USAGE_REPORT:
			trig = models.PolicyControlRequestTrigger_US_RE
		default:
			logger.PolicyAuthorizationlog.Warnln("AF Event is unknown")
			continue
		}
		if !util.CheckPolicyControlReqTrig(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, trig) {
			smPolicy.PolicyDecision.PolicyCtrlReqTriggers = append(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, trig)
			updataSmPolicy = true
		}
	}
	appSessCtx := appSession.AppSessionContext
	// update Context
	if appSessCtx.AscReqData.EvSubsc == nil {
		appSessCtx.AscReqData.EvSubsc = new(models.EventsSubscReqData)
	}
	appSessCtx.AscReqData.EvSubsc.Events = eventsSubscReqData.Events
	appSessCtx.AscReqData.EvSubsc.UsgThres = eventsSubscReqData.UsgThres
	appSessCtx.AscReqData.EvSubsc.NotifUri = eventsSubscReqData.NotifUri
	appSessCtx.EvsNotif = nil
	// update app Session
	appSession.EventUri = eventsSubscReqData.NotifUri
	appSession.Events = eventSubs

	resp := models.UpdateEventsSubscResponse{
		EvSubsc: eventsSubscReqData,
	}
	appSessCtx.EvsNotif = &models.EventsNotification{
		EvSubsUri: eventsSubscReqData.NotifUri,
	}
	// Set Event Subsciption related Data
	if len(eventSubs) > 0 {
		if _, exist := eventSubs[models.AfEvent_PLMN_CHG]; exist {
			afNotif := models.AfEventNotification{
				Event: models.AfEvent_PLMN_CHG,
			}
			appSessCtx.EvsNotif.EvNotifs = append(appSessCtx.EvsNotif.EvNotifs, afNotif)
			plmnID := smPolicy.PolicyContext.ServingNetwork
			if plmnID != nil {
				appSessCtx.EvsNotif.PlmnId = &models.PlmnId{
					Mcc: plmnID.Mcc,
					Mnc: plmnID.Mnc,
				}
			}
		}
		if _, exist := eventSubs[models.AfEvent_ACCESS_TYPE_CHANGE]; exist {
			afNotif := models.AfEventNotification{
				Event: models.AfEvent_ACCESS_TYPE_CHANGE,
			}
			appSessCtx.EvsNotif.EvNotifs = append(appSessCtx.EvsNotif.EvNotifs, afNotif)
			appSessCtx.EvsNotif.AccessType = smPolicy.PolicyContext.AccessType
			appSessCtx.EvsNotif.RatType = smPolicy.PolicyContext.RatType
		}
	}
	if appSessCtx.EvsNotif.EvNotifs == nil {
		appSessCtx.EvsNotif = nil
	}

	resp.EvsNotif = appSessCtx.EvsNotif

	changed := appSession.SmPolicyData.ArrangeExistEventSubscription()

	// Send Notification to SMF
	if updataSmPolicy || changed {
		smPolicyID := fmt.Sprintf("%s-%d", smPolicy.PcfUe.Supi, smPolicy.PolicyContext.PduSessionId)
		notification := models.SmPolicyNotification{
			ResourceUri:      util.GetResourceUri(models.ServiceName_NPCF_SMPOLICYCONTROL, smPolicyID),
			SmPolicyDecision: smPolicy.PolicyDecision,
		}
		notifyevent.DispatchSendSMPolicyUpdateNotifyEvent(smPolicy.PolicyContext.NotificationUri, &notification)
		logger.PolicyAuthorizationlog.Debugf("send SM Policy[%s] Update Notification", smPolicyID)
	}
	if created {
		locationHeader := fmt.Sprintf("%s/events-subscription",
			util.GetResourceUri(models.ServiceName_NPCF_POLICYAUTHORIZATION, appSessID))
		logger.PolicyAuthorizationlog.Debugf("app session Id[%s] Create Subscription", appSessID)
		return &resp, locationHeader, http.StatusCreated, nil
	} else if resp.EvsNotif != nil {
		logger.PolicyAuthorizationlog.Debugf("app session Id[%s] Modify Subscription", appSessID)
		return &resp, "", http.StatusOK, nil
	} else {
		logger.PolicyAuthorizationlog.Debugf("app session Id[%s] Modify Subscription", appSessID)
		return &resp, "", http.StatusNoContent, nil
	}
}

func SendAppSessionTermination(appSession *pcf_context.AppSessionData, request models.TerminationInfo) {
	logger.PolicyAuthorizationlog.Debugln("send App Session Termination")
	if appSession == nil {
		logger.PolicyAuthorizationlog.Warnln("send App Session Termination Error[appSession is nil]")
		return
	}
	uri := appSession.AppSessionContext.AscReqData.NotifUri
	if uri != "" {
		request.ResUri = util.GetResourceUri(models.ServiceName_NPCF_POLICYAUTHORIZATION, appSession.AppSessionId)
		client := util.GetNpcfPolicyAuthorizationCallbackClient()
		httpResponse, err := client.PolicyAuthorizationTerminateRequestApi.PolicyAuthorizationTerminateRequest(
			context.Background(), uri, request)
		if err != nil {
			if httpResponse != nil {
				logger.PolicyAuthorizationlog.Warnf("send App Session Termination Error[%s]", httpResponse.Status)
			} else {
				logger.PolicyAuthorizationlog.Warnf("send App Session Termination Failed[%s]", err.Error())
			}
			return
		} else if httpResponse == nil {
			logger.PolicyAuthorizationlog.Warnln("send App Session Termination Failed[HTTP Response is nil]")
			return
		}
		defer func() {
			if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
				logger.PolicyAuthorizationlog.Errorf(
					"PolicyAuthorizationTerminateRequest response body cannot close: %+v", rspCloseErr)
			}
		}()
		if httpResponse.StatusCode != http.StatusOK && httpResponse.StatusCode != http.StatusNoContent {
			logger.PolicyAuthorizationlog.Warnln("send App Session Termination Failed")
		} else {
			logger.PolicyAuthorizationlog.Debugf("send App Session Termination Success")
		}
	}
}

// Handle Create/ Modify Background Data Transfer Policy Indication
func handleBDTPolicyInd(pcfSelf *pcf_context.PCFContext,
	appSessCtx *models.AppSessionContext,
) (err error) {
	req := appSessCtx.AscReqData

	var requestSuppFeat openapi.SupportedFeature
	if tempRequestSuppFeat, err := openapi.NewSupportedFeature(req.SuppFeat); err != nil {
		logger.PolicyAuthorizationlog.Errorln("sponsored connectivity is disabled by AF")
	} else {
		requestSuppFeat = tempRequestSuppFeat
	}
	respData := models.AppSessionContextRespData{
		ServAuthInfo: models.ServAuthInfo_NOT_KNOWN,
		SuppFeat: pcfSelf.PcfSuppFeats[models.ServiceName_NPCF_POLICYAUTHORIZATION].NegotiateWith(
			requestSuppFeat).String(),
	}
	client := util.GetNudrClient(getDefaultUdrUri(pcfSelf))
	bdtData, resp, err1 := client.DefaultApi.PolicyDataBdtDataBdtReferenceIdGet(context.Background(), req.BdtRefId)
	if err1 != nil {
		return fmt.Errorf("UDR Get BdtData error[%s]", err1.Error())
	} else if resp == nil || resp.StatusCode != http.StatusOK {
		return fmt.Errorf("UDR Get BdtData error")
	} else {
		defer func() {
			if rspCloseErr := resp.Body.Close(); rspCloseErr != nil {
				logger.PolicyAuthorizationlog.Errorf(
					"PolicyDataBdtDataBdtReferenceIdGet response body cannot close: %+v", rspCloseErr)
			}
		}()
		startTime, err1 := time.Parse(util.TimeFormat, bdtData.TransPolicy.RecTimeInt.StartTime)
		if err1 != nil {
			return err1
		}
		stopTime, err1 := time.Parse(util.TimeFormat, bdtData.TransPolicy.RecTimeInt.StopTime)
		if err1 != nil {
			return err1
		}
		if startTime.After(time.Now()) {
			respData.ServAuthInfo = models.ServAuthInfo_NOT_YET_OCURRED
		} else if stopTime.Before(time.Now()) {
			respData.ServAuthInfo = models.ServAuthInfo_EXPIRED
		}
	}
	appSessCtx.AscRespData = &respData
	return nil
}

// provisioning of sponsored connectivity information
func handleSponsoredConnectivityInformation(smPolicy *pcf_context.UeSmPolicyData, relatedPccRuleIds map[string]string,
	aspID, sponID string, sponStatus models.SponsoringStatus, umData *models.UsageMonitoringData,
	updateSMpolicy *bool,
) error {
	if sponStatus == models.SponsoringStatus_DISABLED {
		logger.PolicyAuthorizationlog.Debugln("sponsored connectivity is disabled by AF")
		umID := util.GetUmId(aspID, sponID)
		for _, pccRuleID := range relatedPccRuleIds {
			pccRule := smPolicy.PolicyDecision.PccRules[pccRuleID]
			for _, chgID := range pccRule.RefChgData {
				// disables sponsoring a service
				chgData := smPolicy.PolicyDecision.ChgDecs[chgID]
				if chgData.AppSvcProvId == aspID && chgData.SponsorId == sponID {
					chgData.SponsorId = ""
					chgData.AppSvcProvId = ""
					chgData.ReportingLevel = models.ReportingLevel_SER_ID_LEVEL
					smPolicy.PolicyDecision.ChgDecs[chgID] = chgData
					*updateSMpolicy = true
				}
			}
			if pccRule.RefUmData != nil {
				pccRule.RefUmData = nil
				smPolicy.PolicyDecision.PccRules[pccRuleID] = pccRule
			}
			// disable the usage monitoring
			// TODO: As a result, PCF gets the accumulated usage of the sponsored data connectivity
			delete(smPolicy.PolicyDecision.UmDecs, umID)
		}
	} else {
		if umData != nil {
			supp := util.CheckSuppFeat(smPolicy.PolicyDecision.SuppFeat, 5) // UMC support = 5 in 29512
			if !supp {
				err := fmt.Errorf("usage monitor control is not supported in SMF")
				return err
			}
		}
		chgIDUsed := false
		chgID := util.GetChgId(smPolicy.ChargingIdGenarator)
		for _, pccRuleID := range relatedPccRuleIds {
			pccRule := smPolicy.PolicyDecision.PccRules[pccRuleID]
			chgData := models.ChargingData{
				ChgId: chgID,
			}
			if pccRule.RefChgData != nil {
				chgID := pccRule.RefChgData[0]
				chgData = *smPolicy.PolicyDecision.ChgDecs[chgID]
			} else {
				chgIDUsed = true
			}
			// TODO: PCF, based on operator policies, shall check whether it is required to
			// validate the sponsored connectivity data.
			// If it is required, it shall perform the authorizations based on sponsored data connectivity profiles.
			// If the authorization fails, the PCF shall send HTTP "403 Forbidden" with the "cause" attribute set to
			// "UNAUTHORIZED_SPONSORED_DATA_CONNECTIVITY"
			pccRule.RefChgData = []string{chgData.ChgId}
			chgData.ReportingLevel = models.ReportingLevel_SPON_CON_LEVEL
			chgData.SponsorId = sponID
			chgData.AppSvcProvId = aspID
			if umData != nil {
				pccRule.RefUmData = []string{umData.UmId}
			}
			util.SetPccRuleRelatedData(smPolicy.PolicyDecision, pccRule, nil, nil, &chgData, umData)
			*updateSMpolicy = true
		}
		if chgIDUsed {
			smPolicy.ChargingIdGenarator++
		}
		// TODO: handling UE is roaming in VPLMN case
	}
	return nil
}

func getMaxPrecedence(pccRules map[string]*models.PccRule) (maxVaule int32) {
	maxVaule = 0
	for _, rule := range pccRules {
		if rule.Precedence > maxVaule {
			maxVaule = rule.Precedence
		}
	}
	return
}

func getMaxPccRuleIdNum(pccRules map[string]*models.PccRule) int32 {
	var maxID int32 = 0
	for id := range pccRules {
		if n, err := strconv.Atoi(id); err == nil && int32(n) > maxID {
			maxID = int32(n)
		}
	}
	return maxID
}

/*
func getFlowInfos(comp models.MediaComponent) (flows []models.FlowInformation, err error) {
	for _, subComp := range comp.MedSubComps {
		if subComp.EthfDescs != nil {
			return nil, fmt.Errorf("Flow Description with Mac Address does not support")
		}
		fStatus := subComp.FStatus
		if subComp.FlowUsage == models.FlowUsage_RTCP {
			fStatus = models.FlowStatus_ENABLED
		} else if fStatus == "" {
			fStatus = comp.FStatus
		}
		if fStatus == models.FlowStatus_REMOVED {
			continue
		}
		// gate control
		statusUsage := map[models.FlowDirection]bool{
			models.FlowDirection_UPLINK:   true,
			models.FlowDirection_DOWNLINK: true,
		}
		switch fStatus {
		case models.FlowStatus_ENABLED_UPLINK:
			statusUsage[models.FlowDirection_DOWNLINK] = false
		case models.FlowStatus_ENABLED_DOWNLINK:
			statusUsage[models.FlowDirection_UPLINK] = false
		case models.FlowStatus_DISABLED:
			statusUsage[models.FlowDirection_DOWNLINK] = false
			statusUsage[models.FlowDirection_UPLINK] = false
		}
		for _, desc := range subComp.FDescs {
			flowDesc, flowDir, err := flowDescFromN5toN7(desc)
			if err != nil {
				return nil, err
			}
			flowInfo := models.FlowInformation{
				FlowDescription:   flowDesc,
				FlowDirection:     models.FlowDirectionRm(flowDir),
				PacketFilterUsage: statusUsage[flowDir],
				TosTrafficClass:   subComp.TosTrCl,
			}
			flows = append(flows, flowInfo)
		}
	}
	return
}
*/

func getFlowInfos(subComp *models.MediaSubComponent) ([]models.FlowInformation, error) {
	var flows []models.FlowInformation
	if subComp.EthfDescs != nil {
		return nil, fmt.Errorf("flow description with mac address not supported")
	}
	fStatus := subComp.FStatus
	if subComp.FlowUsage == models.FlowUsage_RTCP {
		fStatus = models.FlowStatus_ENABLED
	}
	if fStatus == models.FlowStatus_REMOVED {
		return nil, nil
	}
	// gate control
	statusUsage := map[models.FlowDirection]bool{
		models.FlowDirection_UPLINK:   true,
		models.FlowDirection_DOWNLINK: true,
	}
	switch fStatus {
	case models.FlowStatus_ENABLED_UPLINK:
		statusUsage[models.FlowDirection_DOWNLINK] = false
	case models.FlowStatus_ENABLED_DOWNLINK:
		statusUsage[models.FlowDirection_UPLINK] = false
	case models.FlowStatus_DISABLED:
		statusUsage[models.FlowDirection_DOWNLINK] = false
		statusUsage[models.FlowDirection_UPLINK] = false
	}
	for _, desc := range subComp.FDescs {
		flowDesc, flowDir, err := flowDescFromN5toN7(desc)
		if err != nil {
			return nil, err
		}
		flowInfo := models.FlowInformation{
			FlowDescription:   flowDesc,
			FlowDirection:     models.FlowDirectionRm(flowDir),
			PacketFilterUsage: statusUsage[flowDir],
			TosTrafficClass:   subComp.TosTrCl,
		}
		flows = append(flows, flowInfo)
	}
	return flows, nil
}

func flowDescFromN5toN7(n5Flow string) (n7Flow string, direction models.FlowDirection, err error) {
	if strings.HasPrefix(n5Flow, "permit out") {
		n7Flow = n5Flow
		direction = models.FlowDirection_DOWNLINK
	} else if strings.HasPrefix(n5Flow, "permit in") {
		n7Flow = strings.ReplaceAll(n5Flow, "permit in", "permit out")
		direction = models.FlowDirection_UPLINK
	} else if strings.HasPrefix(n5Flow, "permit inout") {
		n7Flow = strings.ReplaceAll(n5Flow, "permit inout", "permit out")
		direction = models.FlowDirection_BIDIRECTIONAL
	} else {
		err = fmt.Errorf("invaild flow description[%s]", n5Flow)
	}
	return
}

func updateQosInMedComp(qosData models.QosData, comp *models.MediaComponent) (models.QosData,
	bool, bool,
) {
	var dlExist bool
	var ulExist bool
	updatedQosData := qosData
	if comp.FStatus == models.FlowStatus_REMOVED {
		updatedQosData.MaxbrDl = ""
		updatedQosData.MaxbrUl = ""
		return updatedQosData, ulExist, dlExist
	}
	maxBwUl := 0.0
	maxBwDl := 0.0
	minBwUl := 0.0
	minBwDl := 0.0
	for _, subsComp := range comp.MedSubComps {
		for _, flow := range subsComp.FDescs {
			_, dir, err := flowDescFromN5toN7(flow)
			if err != nil {
				logger.PolicyAuthorizationlog.Errorf(
					"flowDescFromN5toN7 error in updateQosInMedComp: %+v", err)
			}
			both := false
			if dir == models.FlowDirection_BIDIRECTIONAL {
				both = true
			}
			if subsComp.FlowUsage != models.FlowUsage_RTCP {
				// not RTCP
				if both || dir == models.FlowDirection_UPLINK {
					ulExist = true
					if comp.MarBwUl != "" {
						bwUl, err := pcf_context.ConvertBitRateToKbps(comp.MarBwUl)
						if err != nil {
							logger.PolicyAuthorizationlog.Errorf(
								"pcf_context ConvertBitRateToKbps error in updateQosInMedComp: %+v", err)
						}
						maxBwUl += bwUl
					}
					if comp.MirBwUl != "" {
						bwUl, err := pcf_context.ConvertBitRateToKbps(comp.MirBwUl)
						if err != nil {
							logger.PolicyAuthorizationlog.Errorf(
								"pcf_context ConvertBitRateToKbps error in updateQosInMedComp: %+v", err)
						}
						minBwUl += bwUl
					}
				}
				if both || dir == models.FlowDirection_DOWNLINK {
					dlExist = true
					if comp.MarBwDl != "" {
						bwDl, err := pcf_context.ConvertBitRateToKbps(comp.MarBwDl)
						if err != nil {
							logger.PolicyAuthorizationlog.Errorf(
								"pcf_context ConvertBitRateToKbps error in updateQosInMedComp: %+v", err)
						}
						maxBwDl += bwDl
					}
					if comp.MirBwDl != "" {
						bwDl, err := pcf_context.ConvertBitRateToKbps(comp.MirBwDl)
						if err != nil {
							logger.PolicyAuthorizationlog.Errorf(
								"pcf_context ConvertBitRateToKbps error in updateQosInMedComp: %+v", err)
						}
						minBwDl += bwDl
					}
				}
			} else {
				if both || dir == models.FlowDirection_UPLINK {
					ulExist = true
					if subsComp.MarBwUl != "" {
						bwUl, err := pcf_context.ConvertBitRateToKbps(subsComp.MarBwUl)
						if err != nil {
							logger.PolicyAuthorizationlog.Errorf(
								"pcf_context ConvertBitRateToKbps error in updateQosInMedComp: %+v", err)
						}
						maxBwUl += bwUl
					} else if comp.MarBwUl != "" {
						bwUl, err := pcf_context.ConvertBitRateToKbps(comp.MarBwUl)
						if err != nil {
							logger.PolicyAuthorizationlog.Errorf(
								"pcf_context ConvertBitRateToKbps error in updateQosInMedComp: %+v", err)
						}
						maxBwUl += (0.05 * bwUl)
					}
				}
				if both || dir == models.FlowDirection_DOWNLINK {
					dlExist = true
					if subsComp.MarBwDl != "" {
						bwDl, err := pcf_context.ConvertBitRateToKbps(subsComp.MarBwDl)
						if err != nil {
							logger.PolicyAuthorizationlog.Errorf(
								"pcf_context ConvertBitRateToKbps error in updateQosInMedComp: %+v", err)
						}
						maxBwDl += bwDl
					} else if comp.MarBwDl != "" {
						bwDl, err := pcf_context.ConvertBitRateToKbps(comp.MarBwDl)
						if err != nil {
							logger.PolicyAuthorizationlog.Errorf(
								"pcf_context ConvertBitRateToKbps error in updateQosInMedComp: %+v", err)
						}
						maxBwDl += (0.05 * bwDl)
					}
				}
			}
		}
	}
	// update Downlink MBR
	if maxBwDl == 0.0 {
		updatedQosData.MaxbrDl = comp.MarBwDl
	} else {
		updatedQosData.MaxbrDl = pcf_context.ConvertBitRateToString(maxBwDl)
	}
	// update Uplink MBR
	if maxBwUl == 0.0 {
		updatedQosData.MaxbrUl = comp.MarBwUl
	} else {
		updatedQosData.MaxbrUl = pcf_context.ConvertBitRateToString(maxBwUl)
	}
	// if gbr == 0 then assign gbr = mbr

	// update Downlink GBR
	if minBwDl != 0.0 {
		updatedQosData.GbrDl = pcf_context.ConvertBitRateToString(minBwDl)
	}
	// update Uplink GBR
	if minBwUl != 0.0 {
		updatedQosData.GbrUl = pcf_context.ConvertBitRateToString(minBwUl)
	}
	return updatedQosData, ulExist, dlExist
}

func updateQosInMedSubComp(qosData *models.QosData, comp *models.MediaComponent,
	subsComp *models.MediaSubComponent,
) (updatedQosData models.QosData, ulExist, dlExist bool) {
	updatedQosData = *qosData
	if comp.FStatus == models.FlowStatus_REMOVED {
		updatedQosData.MaxbrDl = ""
		updatedQosData.MaxbrUl = ""
		return updatedQosData, false, false
	}
	maxBwUl := 0.0
	maxBwDl := 0.0
	minBwUl := 0.0
	minBwDl := 0.0
	for _, flow := range subsComp.FDescs {
		_, dir, err := flowDescFromN5toN7(flow)
		if err != nil {
			logger.PolicyAuthorizationlog.Errorf(
				"flowDescFromN5toN7 error in updateQosInMedSubComp: %+v", err)
		}
		both := false
		if dir == models.FlowDirection_BIDIRECTIONAL {
			both = true
		}
		if subsComp.FlowUsage != models.FlowUsage_RTCP {
			// not RTCP
			if both || dir == models.FlowDirection_UPLINK {
				ulExist = true
				if comp.MarBwUl != "" {
					bwUl, err := pcf_context.ConvertBitRateToKbps(comp.MarBwUl)
					if err != nil {
						logger.PolicyAuthorizationlog.Errorf(
							"pcf_context ConvertBitRateToKbps error in updateQosInMedSubComp: %+v", err)
					}
					maxBwUl += bwUl
				}
				if comp.MirBwUl != "" {
					bwUl, err := pcf_context.ConvertBitRateToKbps(comp.MirBwUl)
					if err != nil {
						logger.PolicyAuthorizationlog.Errorf(
							"pcf_context ConvertBitRateToKbps error in updateQosInMedSubComp: %+v", err)
					}
					minBwUl += bwUl
				}
			}
			if both || dir == models.FlowDirection_DOWNLINK {
				dlExist = true
				if comp.MarBwDl != "" {
					bwDl, err := pcf_context.ConvertBitRateToKbps(comp.MarBwDl)
					if err != nil {
						logger.PolicyAuthorizationlog.Errorf(
							"pcf_context ConvertBitRateToKbps error in updateQosInMedSubComp: %+v", err)
					}
					maxBwDl += bwDl
				}
				if comp.MirBwDl != "" {
					bwDl, err := pcf_context.ConvertBitRateToKbps(comp.MirBwDl)
					if err != nil {
						logger.PolicyAuthorizationlog.Errorf(
							"pcf_context ConvertBitRateToKbps error in updateQosInMedSubComp: %+v", err)
					}
					minBwDl += bwDl
				}
			}
		} else {
			if both || dir == models.FlowDirection_UPLINK {
				ulExist = true
				if subsComp.MarBwUl != "" {
					bwUl, err := pcf_context.ConvertBitRateToKbps(subsComp.MarBwUl)
					if err != nil {
						logger.PolicyAuthorizationlog.Errorf(
							"pcf_context ConvertBitRateToKbps error in updateQosInMedSubComp: %+v", err)
					}
					maxBwUl += bwUl
				} else if comp.MarBwUl != "" {
					bwUl, err := pcf_context.ConvertBitRateToKbps(comp.MarBwUl)
					if err != nil {
						logger.PolicyAuthorizationlog.Errorf(
							"pcf_context ConvertBitRateToKbps error in updateQosInMedSubComp: %+v", err)
					}
					maxBwUl += (0.05 * bwUl)
				}
			}
			if both || dir == models.FlowDirection_DOWNLINK {
				dlExist = true
				if subsComp.MarBwDl != "" {
					bwDl, err := pcf_context.ConvertBitRateToKbps(subsComp.MarBwDl)
					if err != nil {
						logger.PolicyAuthorizationlog.Errorf(
							"pcf_context ConvertBitRateToKbps error in updateQosInMedSubComp: %+v", err)
					}
					maxBwDl += bwDl
				} else if comp.MarBwDl != "" {
					bwDl, err := pcf_context.ConvertBitRateToKbps(comp.MarBwDl)
					if err != nil {
						logger.PolicyAuthorizationlog.Errorf(
							"pcf_context ConvertBitRateToKbps error in updateQosInMedSubComp: %+v", err)
					}
					maxBwDl += (0.05 * bwDl)
				}
			}
		}
	}

	// update Downlink MBR
	if maxBwDl == 0.0 {
		updatedQosData.MaxbrDl = comp.MarBwDl
	} else {
		updatedQosData.MaxbrDl = pcf_context.ConvertBitRateToString(maxBwDl)
	}
	// update Uplink MBR
	if maxBwUl == 0.0 {
		updatedQosData.MaxbrUl = comp.MarBwUl
	} else {
		updatedQosData.MaxbrUl = pcf_context.ConvertBitRateToString(maxBwUl)
	}
	// if gbr == 0 then assign gbr = mbr
	// update Downlink GBR
	if minBwDl != 0.0 {
		updatedQosData.GbrDl = pcf_context.ConvertBitRateToString(minBwDl)
	}
	// update Uplink GBR
	if minBwUl != 0.0 {
		updatedQosData.GbrUl = pcf_context.ConvertBitRateToString(minBwUl)
	}
	return updatedQosData, ulExist, dlExist
}

func removeMediaComp(appSession *pcf_context.AppSessionData, compN string) {
	idMaps := appSession.RelatedPccRuleIds
	smPolicy := appSession.SmPolicyData
	if idMaps != nil {
		if appSession.AppSessionContext.AscReqData.MedComponents == nil {
			return
		}
		comp, exist := appSession.AppSessionContext.AscReqData.MedComponents[compN]
		if !exist {
			return
		}
		if comp.MedSubComps != nil {
			for fNum := range comp.MedSubComps {
				key := fmt.Sprintf("%s-%s", compN, fNum)
				pccRuleID := idMaps[key]
				err := smPolicy.RemovePccRule(pccRuleID, nil)
				if err != nil {
					logger.PolicyAuthorizationlog.Warnln(err.Error())
				}
				delete(appSession.RelatedPccRuleIds, key)
				delete(appSession.PccRuleIdMapToCompId, pccRuleID)
			}
		} else {
			pccRuleID := idMaps[compN]
			err := smPolicy.RemovePccRule(pccRuleID, nil)
			if err != nil {
				logger.PolicyAuthorizationlog.Warnln(err.Error())
			}
			delete(appSession.RelatedPccRuleIds, compN)
			delete(appSession.PccRuleIdMapToCompId, pccRuleID)
		}
		delete(appSession.AppSessionContext.AscReqData.MedComponents, compN)
	}
}

// func removeMediaSubComp(appSession *pcf_context.AppSessionData, compN, fNum string) {
// 	key := fmt.Sprintf("%s-%s", compN, fNum)
// 	idMaps := appSession.RelatedPccRuleIds
// 	smPolicy := appSession.SmPolicyData
// 	if idMaps != nil {
// 		if appSession.AppSessionContext.AscReqData.MedComponents == nil {
// 			return
// 		}
// 		if comp, exist := appSession.AppSessionContext.AscReqData.MedComponents[compN]; exist {
// 			pccRuleID := idMaps[key]
// 			smPolicy.RemovePccRule(pccRuleID, nil)
// 			delete(appSession.RelatedPccRuleIds, key)
// 			delete(comp.MedSubComps, fNum)
// 			appSession.AppSessionContext.AscReqData.MedComponents[compN] = comp
// 		}
// 	}
// 	return
// }

func threshRmToThresh(threshrm *models.UsageThresholdRm) *models.UsageThreshold {
	if threshrm == nil {
		return nil
	}
	return &models.UsageThreshold{
		Duration:       threshrm.Duration,
		TotalVolume:    threshrm.TotalVolume,
		DownlinkVolume: threshrm.DownlinkVolume,
		UplinkVolume:   threshrm.UplinkVolume,
	}
}

func extractUmData(umID string, eventSubs map[models.AfEvent]models.AfNotifMethod,
	threshold *models.UsageThreshold,
) (umData *models.UsageMonitoringData, err error) {
	if _, umExist := eventSubs[models.AfEvent_USAGE_REPORT]; umExist {
		if threshold == nil {
			return nil, fmt.Errorf("UsageThreshold is nil in USAGE REPORT Subscription")
		} else {
			tmp := util.CreateUmData(umID, *threshold)
			umData = &tmp
		}
	}
	return
}

func modifyRemainBitRate(smPolicy *pcf_context.UeSmPolicyData, qosData *models.QosData,
	ulExist, dlExist bool,
) *models.ProblemDetails {
	// if request GBR == 0, qos GBR = MBR
	// if request GBR > remain GBR, qos GBR = remain GBR
	if ulExist {
		if qosData.GbrUl == "" {
			// err = pcf_context.DecreaseRamainBitRate(smPolicy.RemainGbrUL, qosData.MaxbrUl)
			if err := pcf_context.DecreaseRamainBitRate(smPolicy.RemainGbrUL, qosData.MaxbrUl); err != nil {
				qosData.GbrUl = pcf_context.DecreaseRamainBitRateToZero(smPolicy.RemainGbrUL)
			} else {
				qosData.GbrUl = qosData.MaxbrUl
			}
		} else {
			// err = pcf_context.DecreaseRamainBitRate(smPolicy.RemainGbrUL, qosData.GbrUl)
			if err := pcf_context.DecreaseRamainBitRate(smPolicy.RemainGbrUL, qosData.GbrUl); err != nil {
				problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
				// sendProblemDetail(httpChannel, err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
				return &problemDetail
			}
		}
	}
	if dlExist {
		if qosData.GbrDl == "" {
			// err = pcf_context.DecreaseRamainBitRate(smPolicy.RemainGbrDL, qosData.MaxbrDl)
			if err := pcf_context.DecreaseRamainBitRate(smPolicy.RemainGbrDL, qosData.MaxbrDl); err != nil {
				qosData.GbrDl = pcf_context.DecreaseRamainBitRateToZero(smPolicy.RemainGbrDL)
			} else {
				qosData.GbrDl = qosData.MaxbrDl
			}
		} else {
			// err = pcf_context.DecreaseRamainBitRate(smPolicy.RemainGbrDL, qosData.GbrDl)
			if err := pcf_context.DecreaseRamainBitRate(smPolicy.RemainGbrDL, qosData.GbrDl); err != nil {
				// if Policy failed, revert remain GBR to original GBR
				pcf_context.IncreaseRamainBitRate(smPolicy.RemainGbrUL, qosData.GbrUl)
				problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
				// sendProblemDetail(httpChannel, err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
				return &problemDetail
			}
		}
	}
	return nil
}

func provisioningOfTrafficRoutingInfo(smPolicy *pcf_context.UeSmPolicyData, appID string,
	routeReq *models.AfRoutingRequirement, fStatus models.FlowStatus,
) *models.PccRule {
	var tcData *models.TrafficControlData

	// TODO : handle temporal or spatial validity
	pccRule := util.GetPccRuleByAfAppId(smPolicy.PolicyDecision.PccRules, appID)
	if pccRule != nil {
		// Update TcData
		var tcID string
		if len(pccRule.RefTcData) > 0 {
			// 1 PCC rule only supports 1 TrafficControlData
			// TODO: 1 PCC rule supports multiple TrafficControlData
			// Re-use the original tcID
			tcID = pccRule.RefTcData[0]
			if smPolicy.PolicyDecision.TraffContDecs == nil {
				logger.PolicyAuthorizationlog.Errorf("TraffContDecs is nil, tcID[%s]", tcID)
				tcData = util.CreateTcData(0, tcID, fStatus)
			} else {
				tcData = smPolicy.PolicyDecision.TraffContDecs[tcID]
				if tcData == nil {
					logger.PolicyAuthorizationlog.Errorf("TraffContDecs[%s] not found", tcID)
					tcData = util.CreateTcData(0, tcID, fStatus)
				}
			}
		} else {
			// tcID's number equals to pccRuleID's number
			tcID = strings.ReplaceAll(pccRule.PccRuleId, "PccRule", "Tc")
			tcData = util.CreateTcData(0, tcID, fStatus)
			pccRule.RefTcData = []string{tcID}
		}
		tcData.RouteToLocs = routeReq.RouteToLocs
		tcData.UpPathChgEvent = routeReq.UpPathChgSub
		pccRule.AppReloc = routeReq.AppReloc
		util.SetPccRuleRelatedData(smPolicy.PolicyDecision, pccRule, tcData, nil, nil, nil)
		logger.PolicyAuthorizationlog.Infof("Update Traffic Control Data[%s] in PCC rule[%s]",
			tcID, pccRule.PccRuleId)
	} else {
		// Create a Pcc Rule if afappID dose not match any pcc rule
		maxPrecedence := getMaxPrecedence(smPolicy.PolicyDecision.PccRules)
		pccRule = util.CreatePccRule(smPolicy.PccRuleIdGenarator, maxPrecedence+1, nil, appID)
		tcData = util.CreateTcData(smPolicy.PccRuleIdGenarator, "", fStatus)
		tcData.RouteToLocs = routeReq.RouteToLocs
		tcData.UpPathChgEvent = routeReq.UpPathChgSub
		pccRule.RefTcData = []string{tcData.TcId}
		util.SetPccRuleRelatedData(smPolicy.PolicyDecision, pccRule, tcData, nil, nil, nil)
		smPolicy.PccRuleIdGenarator++
		logger.PolicyAuthorizationlog.Infof("create PCC rule[%s] with new Traffic Control Data[%s]",
			pccRule.PccRuleId, tcData.TcId)
	}
	return pccRule
}

func reverseStringMap(srcMap map[string]string) map[string]string {
	if srcMap == nil {
		return nil
	}
	reverseMap := make(map[string]string)
	for key, value := range srcMap {
		reverseMap[value] = key
	}
	return reverseMap
}
