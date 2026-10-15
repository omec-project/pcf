// SPDX-FileCopyrightText: 2025 Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package producer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/internal/notifyevent"
	"github.com/omec-project/pcf/logger"
	stats "github.com/omec-project/pcf/metrics"
	"github.com/omec-project/pcf/util"
	"github.com/omec-project/util/httpwrapper"
)

const appSessionCallbackTimeout = 10 * time.Second

var appSessionCallbackHTTPClient = &http.Client{Timeout: appSessionCallbackTimeout}

func postAppSessionCallbackJSON(uri string, request any, callbackName string) {
	payload, err := json.Marshal(request)
	if err != nil {
		logger.PolicyAuthorizationLog.Warnf("send %s Failed to marshal request[%s]", callbackName, err.Error())
		return
	}

	requestCtx, cancel := context.WithTimeout(context.Background(), appSessionCallbackTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, uri, bytes.NewReader(payload))
	if err != nil {
		logger.PolicyAuthorizationLog.Warnf("send %s Failed to build request[%s]", callbackName, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	httpResponse, err := appSessionCallbackHTTPClient.Do(req)
	if err != nil {
		if httpResponse != nil {
			logger.PolicyAuthorizationLog.Warnf("send %s Error[%s]", callbackName, httpResponse.Status)
		} else {
			logger.PolicyAuthorizationLog.Warnf("send %s Failed[%s]", callbackName, err.Error())
		}
		return
	} else if httpResponse == nil {
		logger.PolicyAuthorizationLog.Warnf("send %s Failed[HTTP Response is nil]", callbackName)
		return
	}
	defer func() {
		if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
			logger.PolicyAuthorizationLog.Errorf("%s response body cannot close: %+v", callbackName, rspCloseErr)
		}
	}()
	if httpResponse.StatusCode != http.StatusOK && httpResponse.StatusCode != http.StatusNoContent {
		logger.PolicyAuthorizationLog.Warnf("send %s Failed", callbackName)
	} else {
		logger.PolicyAuthorizationLog.Debugf("send %s Success", callbackName)
	}
}

func transferAfRoutReqRmToAfRoutReq(AfRoutReqRm models.AfRoutingRequirementRm) models.AfRoutingRequirement {
	spVal := models.SpatialValidity{
		PresenceInfoList: AfRoutReqRm.SpVal.Get().GetPresenceInfoList(),
	}
	afRoutReq := models.AfRoutingRequirement{
		AppReloc:     AfRoutReqRm.AppReloc,
		RouteToLocs:  AfRoutReqRm.RouteToLocs,
		SpVal:        &spVal,
		TempVals:     AfRoutReqRm.TempVals,
		UpPathChgSub: AfRoutReqRm.UpPathChgSub,
	}
	return afRoutReq
}

// transferQosMonitoringInformationRmToQosMonitoringInformation only copies fields that
// were present in the removal model, preserving optional-field absence.
func transferQosMonitoringInformationRmToQosMonitoringInformation(qosMonRm *models.QosMonitoringInformationRm) *models.QosMonitoringInformation {
	qosMon := models.NewQosMonitoringInformation()
	if qosMonRm.HasRepThreshDl() {
		qosMon.SetRepThreshDl(qosMonRm.GetRepThreshDl())
	}
	if qosMonRm.HasRepThreshUl() {
		qosMon.SetRepThreshUl(qosMonRm.GetRepThreshUl())
	}
	if qosMonRm.HasRepThreshRp() {
		qosMon.SetRepThreshRp(qosMonRm.GetRepThreshRp())
	}
	if qosMonRm.HasRepThreshDatRateUl() {
		qosMon.SetRepThreshDatRateUl(qosMonRm.GetRepThreshDatRateUl())
	}
	if qosMonRm.HasRepThreshDatRateDl() {
		qosMon.SetRepThreshDatRateDl(qosMonRm.GetRepThreshDatRateDl())
	}
	if qosMonRm.HasConThreshDl() {
		qosMon.SetConThreshDl(qosMonRm.GetConThreshDl())
	}
	if qosMonRm.HasConThreshUl() {
		qosMon.SetConThreshUl(qosMonRm.GetConThreshUl())
	}
	return qosMon
}

// transferUsageThresholdRmToUsageThreshold only copies fields that were present in the
// removal model, preserving optional-field absence.
func transferUsageThresholdRmToUsageThreshold(usgThresRm *models.UsageThresholdRm) *models.UsageThreshold {
	usgThres := models.NewUsageThreshold()
	if usgThresRm.HasDuration() {
		usgThres.SetDuration(usgThresRm.GetDuration())
	}
	if usgThresRm.HasTotalVolume() {
		usgThres.SetTotalVolume(usgThresRm.GetTotalVolume())
	}
	if usgThresRm.HasDownlinkVolume() {
		usgThres.SetDownlinkVolume(usgThresRm.GetDownlinkVolume())
	}
	if usgThresRm.HasUplinkVolume() {
		usgThres.SetUplinkVolume(usgThresRm.GetUplinkVolume())
	}
	return usgThres
}

func transferMedCompRmToMedComp(medCompRm *models.MediaComponentRm) *models.MediaComponent {
	medSubComps := make(map[string]models.MediaSubComponent)
	for id, medSubCompRm := range medCompRm.GetMedSubComps() {
		evSubscRm := medSubCompRm.EvSubsc.Get()
		qosMon := transferQosMonitoringInformationRmToQosMonitoringInformation(evSubscRm.QosMon.Get())
		qosMonDatRate := transferQosMonitoringInformationRmToQosMonitoringInformation(evSubscRm.QosMonDatRate.Get())
		pdvMon := transferQosMonitoringInformationRmToQosMonitoringInformation(evSubscRm.PdvMon.Get())
		congestMon := transferQosMonitoringInformationRmToQosMonitoringInformation(evSubscRm.CongestMon.Get())
		usgThres := transferUsageThresholdRmToUsageThreshold(evSubscRm.UsgThres.Get())
		evSubsc := models.NewEventsSubscReqData(evSubscRm.GetEvents())
		evSubsc.SetNotifUri(evSubscRm.GetNotifUri())
		evSubsc.SetReqQosMonParams(evSubscRm.GetReqQosMonParams())
		evSubsc.SetQosMon(*qosMon)
		evSubsc.SetQosMonDatRate(*qosMonDatRate)
		evSubsc.SetPdvReqMonParams(evSubscRm.GetPdvReqMonParams())
		evSubsc.SetPdvMon(*pdvMon)
		evSubsc.SetCongestMon(*congestMon)
		evSubsc.SetReqAnis(evSubscRm.GetReqAnis())
		evSubsc.SetUsgThres(*usgThres)
		evSubsc.SetNotifCorreId(evSubscRm.GetNotifCorreId())
		evSubsc.SetAvrgWndw(*evSubscRm.AvrgWndw.Get())
		medSubComps[id] = models.MediaSubComponent{
			AfSigProtocol:    medSubCompRm.AfSigProtocol,
			EthfDescs:        medSubCompRm.GetEthfDescs(),
			FNum:             medSubCompRm.GetFNum(),
			FDescs:           medSubCompRm.GetFDescs(),
			AddInfoFlowDescs: medSubCompRm.GetAddInfoFlowDescs(),
			FStatus:          medSubCompRm.FStatus,
			MarBwDl:          medSubCompRm.MarBwDl.Get(),
			MarBwUl:          medSubCompRm.MarBwUl.Get(),
			TosTrCl:          medSubCompRm.TosTrCl.Get(),
			FlowUsage:        medSubCompRm.FlowUsage,
			EvSubsc:          evSubsc,
		}
	}
	medComp := models.NewMediaComponent(medCompRm.GetMedCompN())
	if medCompRm.HasAfAppId() {
		medComp.SetAfAppId(medCompRm.GetAfAppId())
	}
	if medCompRm.HasAfRoutReq() {
		medComp.SetAfRoutReq(transferAfRoutReqRmToAfRoutReq(medCompRm.GetAfRoutReq()))
	}
	if medCompRm.HasContVer() {
		medComp.SetContVer(medCompRm.GetContVer())
	}
	medComp.SetCodecs(medCompRm.GetCodecs())
	if medCompRm.HasFStatus() {
		medComp.SetFStatus(medCompRm.GetFStatus())
	}
	if medCompRm.HasMarBwDl() {
		medComp.SetMarBwDl(medCompRm.GetMarBwDl())
	}
	if medCompRm.HasMarBwUl() {
		medComp.SetMarBwUl(medCompRm.GetMarBwUl())
	}
	medComp.SetMedSubComps(medSubComps)
	if medCompRm.HasMedType() {
		medComp.SetMedType(medCompRm.GetMedType())
	}
	if medCompRm.HasMirBwDl() {
		medComp.SetMirBwDl(medCompRm.GetMirBwDl())
	}
	if medCompRm.HasMirBwUl() {
		medComp.SetMirBwUl(medCompRm.GetMirBwUl())
	}
	if medCompRm.HasResPrio() {
		medComp.SetResPrio(medCompRm.GetResPrio())
	}
	return medComp
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
	logger.PolicyAuthorizationLog.Debugln("handle Create AppSessions")

	appSessCtx := request.Body.(models.AppSessionContext)

	response, locationHeader, problemDetails := postAppSessCtxProcedure(&appSessCtx)

	if response != nil {
		headers := http.Header{
			locationHeaderKey: {locationHeader},
		}
		stats.IncrementPcfPolicyAuthorizationStats("create", "application_sessions", "SUCCESS")
		return httpwrapper.NewResponse(http.StatusCreated, headers, response)
	} else if problemDetails != nil {
		stats.IncrementPcfPolicyAuthorizationStats("create", "application_sessions", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	stats.IncrementPcfPolicyAuthorizationStats("create", "events_subscription", "FAILURE")
	return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
}

func postAppSessCtxProcedure(appSessCtx *models.AppSessionContext) (*models.AppSessionContext,
	string, *models.ProblemDetails,
) {
	ascReqData := appSessCtx.AscReqData
	pcfSelf := pcfContext.PCF_Self()

	// Initial BDT policy indication(the only one which is not related to session)
	if ascReqData.Get().GetBdtRefId() != "" {
		logger.PolicyAuthorizationLog.Infof("handling BDT Policy Indication for BdtRefId: %s", ascReqData.Get().GetBdtRefId())
		if err := handleBDTPolicyInd(pcfSelf, appSessCtx); err != nil {
			problemDetail := util.GetProblemDetail(err.Error(), util.ERROR_REQUEST_PARAMETERS)
			logger.PolicyAuthorizationLog.Errorf("BDT Policy Indication failed: %v", err)
			return nil, "", problemDetail
		}
		appSessID := fmt.Sprintf("BdtRefId-%s", ascReqData.Get().GetBdtRefId())
		data := pcfContext.AppSessionData{
			AppSessionId:      appSessID,
			AppSessionContext: appSessCtx,
		}
		pcfSelf.AppSessionPool.Store(appSessID, &data)
		locationHeader := util.GetResourceUri(models.SERVICENAME_NPCF_POLICYAUTHORIZATION, appSessID)
		logger.PolicyAuthorizationLog.Infof("app Session Id[%s] Create", appSessID)
		return appSessCtx, locationHeader, nil
	}
	if ascReqData.Get().GetUeIpv4() == "" && ascReqData.Get().GetUeIpv6() == "" && ascReqData.Get().GetUeMac() == "" {
		logger.PolicyAuthorizationLog.Errorln("UE address identifiers are all empty (IPv4/IPv6/MAC)")
		problemDetail := util.GetProblemDetail("UE address identifiers are all empty (IPv4/IPv6/MAC)", util.ERROR_REQUEST_PARAMETERS)
		return nil, "", problemDetail
	}
	if ascReqData.Get().AfRoutReq != nil && ascReqData.Get().GetDnn() == "" {
		logger.PolicyAuthorizationLog.Errorln("DNN missing when AF Routing Requirement is provided")
		problemDetail := util.GetProblemDetail("DNN shall be present", util.ERROR_REQUEST_PARAMETERS)
		return nil, "", problemDetail
	}
	var smPolicy *pcfContext.UeSmPolicyData
	if tempSmPolicy, err := pcfSelf.SessionBinding(ascReqData.Get()); err != nil {
		problemDetail := util.GetProblemDetail(fmt.Sprintf("Session Binding failed[%s]",
			err.Error()), util.PDU_SESSION_NOT_AVAILABLE)
		return nil, "", problemDetail
	} else {
		smPolicy = tempSmPolicy
	}
	logger.PolicyAuthorizationLog.Infof("session Binding Success - UeIpv4[%s], UeIpv6[%s], UeMac[%s]",
		ascReqData.Get().GetUeIpv4(), ascReqData.Get().GetUeIpv6(), ascReqData.Get().GetUeMac())
	ue := smPolicy.PcfUe
	updateSMpolicy := false

	var requestSuppFeat *pcfContext.SupportedFeature
	if tempRequestSuppFeat, err := pcfContext.NewSupportedFeature(ascReqData.Get().SuppFeat); err != nil {
		logger.PolicyAuthorizationLog.Errorln(err.Error())
	} else {
		requestSuppFeat = tempRequestSuppFeat
	}

	pcfSuppFeats := pcfSelf.PcfSuppFeats[models.SERVICENAME_NPCF_POLICYAUTHORIZATION]
	request, err := (&pcfSuppFeats).NegotiateWith(requestSuppFeat)
	if err != nil {
		logger.PolicyAuthorizationLog.Errorln(err.Error())
	}
	nSuppFeat := request.String()
	// InfluenceOnTrafficRouting = 1 in 29514 &  Traffic Steering Control support = 1 in 29512
	traffRoutSupp := util.CheckSuppFeat(nSuppFeat, 1) && util.CheckSuppFeat(smPolicy.PolicyDecision.GetSuppFeat(), 1)
	relatedPccRuleIds := make(map[string]string)
	logger.PolicyAuthorizationLog.Infof("negotiated Supported Feature: %s", nSuppFeat)
	logger.PolicyAuthorizationLog.Infof("traffic Routing Supported: %t", traffRoutSupp)

	if ascReqData.Get().HasMedComponents() {
		// Handle Pcc rules
		var arp int32 = 1
		maxPrecedence := getMaxPrecedence(smPolicy.PolicyDecision.PccRules)
		logger.PolicyAuthorizationLog.Infof("processing %d MediaComponents", len(ascReqData.Get().GetMedComponents()))
		for _, medComp := range ascReqData.Get().GetMedComponents() {
			var pccRule *models.PccRule
			var appID string
			var routeReq *models.AfRoutingRequirement
			// TODO: use specific algorithm instead of default, details in subsclause 7.3.3 of TS 29513
			var var5qi int32 = 9
			if medComp.GetMedType() != "" {
				var5qi = util.MediaTypeTo5qiMap[medComp.GetMedType()]
			}
			logger.PolicyAuthorizationLog.Infof("processing Media Component[%d]", medComp.GetMedCompN())
			if medComp.HasMedSubComps() {
				logger.PolicyAuthorizationLog.Infof("handling Media Component [%d] with %d sub-components", medComp.GetMedCompN(), len(medComp.GetMedSubComps()))
				var allFlowInfos []models.FlowInformation
				var medSubCompsList []models.MediaSubComponent
				for _, medSubComp := range medComp.GetMedSubComps() {
					logger.PolicyAuthorizationLog.Debugf("extracting FlowInfos for FNum [%d]", medSubComp.GetFNum())

					if flowInfos, err := getFlowInfos(&medSubComp); err != nil {
						logger.PolicyAuthorizationLog.Errorf("failed to get FlowInfos for FNum [%d]: %v", medSubComp.GetFNum(), err)
						problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
						return nil, "", problemDetail
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
					key := fmt.Sprintf("%d-%d", medComp.GetMedCompN(), medSubComp.GetFNum())
					relatedPccRuleIds[key] = pccRule.PccRuleId
					logger.PolicyAuthorizationLog.Debugf("mapped PCC Rule ID [%s] to MediaSubComp Key [%s]", pccRule.GetPccRuleId(), key)
				}
				updateSMpolicy = true
				maxPrecedence = getMaxPrecedence(smPolicy.PolicyDecision.GetPccRules())
				continue
			} else if medComp.GetAfAppId() != "" {
				appID = medComp.GetAfAppId()
				routeReq = medComp.AfRoutReq
				logger.PolicyAuthorizationLog.Debugf("using AF App ID [%s] and RouteReq [%v] from Media Component [%d]", appID, routeReq, medComp.GetMedCompN())
			} else if ascReqData.Get().GetAfAppId() != "" {
				appID = ascReqData.Get().GetAfAppId()
				routeReq = ascReqData.Get().AfRoutReq
				logger.PolicyAuthorizationLog.Debugf("using AF App ID [%s] and RouteReq [%v] from AppSessionContext", appID, routeReq)
			} else {
				logger.PolicyAuthorizationLog.Warnf("media Component [%d] lacks both sub-components and AfAppId", medComp.GetMedCompN())
				problemDetail := util.GetProblemDetail("Media Component needs flows of subComp or afAppId",
					util.REQUESTED_SERVICE_NOT_AUTHORIZED)
				return nil, "", problemDetail
			}
			// Find pccRule by AfAppId, otherwise create a new pcc rule
			logger.PolicyAuthorizationLog.Debugf("AfAppId: %s", appID)
			_, existingPccRule, found := util.GetPccRuleByAfAppId(smPolicy.PolicyDecision.GetPccRules(), appID)
			if !found {
				logger.PolicyAuthorizationLog.Infof("no existing PCC Rule found for AppID: %s, creating a new one", appID)
				maxExisting := getMaxPccRuleIdNum(smPolicy.PolicyDecision.GetPccRules())
				if smPolicy.PccRuleIdGenarator <= maxExisting {
					smPolicy.PccRuleIdGenarator = maxExisting + 1
				}
				pccRule = util.CreatePccRule(smPolicy.PccRuleIdGenarator, maxPrecedence+1, nil, appID)

				// Set QoS Data
				// TODO: use real ARP
				qosData := util.CreateQosData(smPolicy.PccRuleIdGenarator, var5qi, arp)
				logger.PolicyAuthorizationLog.Debugf("created QoS Data with QosID: %s, 5QI: %d, ARP: %d", qosData.GetQosId(), qosData.GetVar5qi(), qosData.Arp.GetPriorityLevel())

				if var5qi <= 4 {
					// update QoS Data according to request BitRate
					var ul, dl bool
					qosData, ul, dl = updateQosInMedComp(qosData, &medComp)
					logger.PolicyAuthorizationLog.Debugf("updated QoS Bitrate: QosID: %s, UL changed: %v, DL changed: %v", qosData.GetQosId(), ul, dl)

					if problemDetails := modifyRemainBitRate(smPolicy, &qosData, ul, dl); problemDetails != nil {
						logger.PolicyAuthorizationLog.Errorf("failed to modify remaining bitrate: %v", problemDetails)
						return nil, "", problemDetails
					}
				}
				util.SetPccRuleRelatedData(smPolicy.PolicyDecision, pccRule, nil, &qosData, nil, nil)
				logger.PolicyAuthorizationLog.Debugf("set PCC Rule Related Data for RuleID: %s", pccRule.GetPccRuleId())

				smPolicy.PccRuleIdGenarator++
				maxPrecedence++
				logger.PolicyAuthorizationLog.Debugf("new PCC Rule created: RuleID: %s, AppID: %s, QosID: %s", pccRule.GetPccRuleId(), appID, qosData.GetQosId())
			} else {
				pccRule = &existingPccRule
				logger.PolicyAuthorizationLog.Debugf("found existing PCC Rule for AppID: %s, RuleID: %s", appID, pccRule.GetPccRuleId())
				// update pccRule's qos
				for _, qosID := range pccRule.GetRefQosData() {
					if !smPolicy.PolicyDecision.HasQosDecs() {
						logger.PolicyAuthorizationLog.Errorf("smPolicy.PolicyDecision.QosDecs is nil")
						problemDetail := util.GetProblemDetail("smPolicy.PolicyDecision.QosDecs is nil", util.PDU_SESSION_NOT_AVAILABLE)
						return nil, "", problemDetail
					}
					qosDecs := smPolicy.PolicyDecision.GetQosDecs()
					qosData, ok := qosDecs[qosID]
					if !ok {
						continue
					}
					logger.PolicyAuthorizationLog.Debugf("evaluating existing QoS Data for update: QosID: %s, Var5QI: %d", qosData.GetQosId(), qosData.GetVar5qi())
					if qosData.GetVar5qi() != var5qi || var5qi > 4 {
						continue
					}

					var ul, dl bool
					qosData, ul, dl = updateQosInMedComp(qosData, &medComp)
					logger.PolicyAuthorizationLog.Infof("QoS Update check passed: QosID: %s, UL changed: %v, DL changed: %v", qosData.GetQosId(), ul, dl)
					if problemDetails := modifyRemainBitRate(smPolicy, &qosData, ul, dl); problemDetails != nil {
						logger.PolicyAuthorizationLog.Errorf("failed to modify remaining bitrate during QoS update: %v", problemDetails)
						return nil, "", problemDetails
					}
					qosDecs[qosData.GetQosId()] = qosData
					logger.PolicyAuthorizationLog.Debugf("QoS Data updated: QosID: %s", qosData.GetQosId())
				}
			}
			// Initial provisioning of traffic routing information
			if traffRoutSupp {
				pccRule = provisioningOfTrafficRoutingInfo(smPolicy, appID, routeReq, medComp.GetFStatus())
			}
			key := fmt.Sprintf("%d", medComp.GetMedCompN())
			relatedPccRuleIds[key] = pccRule.GetPccRuleId()
			updateSMpolicy = true
		}
	} else if ascReqData.Get().GetAfAppId() != "" {
		// Initial provisioning of traffic routing information
		req := ascReqData.Get()
		if !req.HasAfRoutReq() || !traffRoutSupp {
			problemDetail := util.GetProblemDetail("Traffic routing not supported", util.REQUESTED_SERVICE_NOT_AUTHORIZED)
			return nil, "", problemDetail
		}
		afAppID := req.GetAfAppId()
		logger.PolicyAuthorizationLog.Infof("af influence on Traffic Routing - AppId[%s]", afAppID)
		pccRule := provisioningOfTrafficRoutingInfo(smPolicy, afAppID, req.AfRoutReq, "")
		key := fmt.Sprintf("appID-%s", afAppID)
		relatedPccRuleIds[key] = pccRule.GetPccRuleId()
		updateSMpolicy = true
	} else {
		problemDetail := util.GetProblemDetail("AF Request need AfAppId or Media Component to match Service Data Flow",
			util.ERROR_REQUEST_PARAMETERS)
		return nil, "", problemDetail
	}

	// Event Subscription
	eventSubs := make(map[models.AfEventPcf]models.AfNotifMethod)
	if ascReqData.Get().HasEvSubsc() {
		for _, subs := range ascReqData.Get().GetEvSubsc().Events {
			if subs.GetNotifMethod() == "" {
				// default value "EVENT_DETECTION"
				subs.SetNotifMethod(models.AFNOTIFMETHOD_EVENT_DETECTION)
				logger.PolicyAuthorizationLog.Infof("af Event [%v] missing NotifMethod, set default [%v]",
					subs.Event, subs.NotifMethod)
			}
			eventSubs[subs.GetEvent()] = subs.GetNotifMethod()
			logger.PolicyAuthorizationLog.Infof("subscribed AF Event [%v] with NotifMethod [%v]", subs.GetEvent(), subs.GetNotifMethod())
			var trig models.PolicyControlRequestTrigger
			switch subs.GetEvent() {
			case models.AFEVENTPCF_ACCESS_TYPE_CHANGE:
				trig = models.POLICYCONTROLREQUESTTRIGGER_AC_TY_CH
			// case models.AFEVENTPCF_FAILED_RESOURCES_ALLOCATION:
			// 	// Subscription to Service Data Flow Deactivation
			// 	trig = models.POLICYCONTROLREQUESTTRIGGER_RES_RELEASE
			case models.AFEVENTPCF_PLMN_CHG:
				trig = models.POLICYCONTROLREQUESTTRIGGER_PLMN_CH
			case models.AFEVENTPCF_QOS_NOTIF:
				// Subscriptions to Service Data Flow QoS notification control
				for _, pccRuleID := range relatedPccRuleIds {
					pccRule := smPolicy.PolicyDecision.GetPccRules()[pccRuleID]
					for _, qosID := range pccRule.GetRefQosData() {
						if smPolicy.PolicyDecision.GetQosDecs() != nil {
							if qosData, ok := smPolicy.PolicyDecision.GetQosDecs()[qosID]; ok {
								qosData.SetQnc(true)
								smPolicy.PolicyDecision.GetQosDecs()[qosID] = qosData
							} else {
								logger.PolicyAuthorizationLog.Warnf("  QoS Data reference [%s] not found in PolicyDecision", qosID)
							}
						}
					}
				}
				trig = models.POLICYCONTROLREQUESTTRIGGER_QOS_NOTIF
			case models.AFEVENTPCF_SUCCESSFUL_RESOURCES_ALLOCATION:
				// Subscription to resources allocation outcome
				trig = models.POLICYCONTROLREQUESTTRIGGER_SUCC_RES_ALLO
			case models.AFEVENTPCF_USAGE_REPORT:
				trig = models.POLICYCONTROLREQUESTTRIGGER_US_RE
			default:
				logger.PolicyAuthorizationLog.Warnf("af Event [%v] is unknown, skipping", subs.GetEvent())
				continue
			}

			// Check and append trigger
			if !util.CheckPolicyControlReqTrig(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, trig) {
				smPolicy.PolicyDecision.PolicyCtrlReqTriggers = append(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, trig)
				updateSMpolicy = true
			} else {
				logger.PolicyAuthorizationLog.Infof("trigger [%v] already exists, skipping add", trig)
			}
		}
	} else {
		logger.PolicyAuthorizationLog.Infof("no AF Event Subscriptions present in request")
	}

	// Initial provisioning of sponsored connectivity information
	if ascReqData.Get().GetAspId() != "" && ascReqData.Get().GetSponId() != "" {
		// SponsoredConnectivity = 2 in 29514 &  SponsoredConnectivity support = 12 in 29512
		logger.PolicyAuthorizationLog.Infof("sponsored Connectivity Requested: AspId=%s, SponId=%s", ascReqData.Get().GetAspId(), ascReqData.Get().GetSponId())
		supp := util.CheckSuppFeat(nSuppFeat, 2) && util.CheckSuppFeat(smPolicy.PolicyDecision.GetSuppFeat(), 12)
		if !supp {
			problemDetail := util.GetProblemDetail("Sponsored Connectivity not supported", util.REQUESTED_SERVICE_NOT_AUTHORIZED)
			logger.PolicyAuthorizationLog.Errorln("sponsored Connectivity not supported by UE or Policy Decision")
			return nil, "", problemDetail
		}
		umID := util.GetUmId(ascReqData.Get().GetAspId(), ascReqData.Get().GetSponId())
		var umData *models.UsageMonitoringData
		var threshold *models.UsageThreshold
		if ascReqData.Get().HasEvSubsc() {
			threshold = ascReqData.Get().GetEvSubsc().UsgThres
		}
		if tempUmData, err := extractUmData(umID, eventSubs, threshold); err != nil {
			problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
			logger.PolicyAuthorizationLog.Errorf("error extracting UsageMonitoringData: %v", err)
			return nil, "", problemDetail
		} else {
			umData = tempUmData
		}
		if err := handleSponsoredConnectivityInformation(smPolicy, relatedPccRuleIds, ascReqData.Get().GetAspId(),
			ascReqData.Get().GetSponId(), ascReqData.Get().GetSponStatus(), umData, &updateSMpolicy); err != nil {
			problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
			logger.PolicyAuthorizationLog.Errorf("failed to handle Sponsored Connectivity: %v", err)
			return nil, "", problemDetail
		}
	}

	// Allocate App Session Id
	appSessID := ue.AllocUeAppSessionId(pcfSelf)
	ascRespData := models.AppSessionContextRespData{}
	ascRespData.SetSuppFeat(nSuppFeat)
	appSessCtx.SetAscRespData(ascRespData)
	// Associate App Session to SMPolicy
	smPolicy.AddAppSession(appSessID)
	data := pcfContext.AppSessionData{
		AppSessionId:      appSessID,
		AppSessionContext: appSessCtx,
		SmPolicyData:      smPolicy,
	}
	logger.PolicyAuthorizationLog.Infof("created/updated AppSession with ID [%s]", appSessID)
	logger.PolicyAuthorizationLog.Debugf("appSession Context: %+v", appSessCtx)
	logger.PolicyAuthorizationLog.Debugf("sm Policy associated with AppSession [%s]: %+v", appSessID, smPolicy)
	if len(relatedPccRuleIds) > 0 {
		data.RelatedPccRuleIds = relatedPccRuleIds
		data.PccRuleIdMapToCompId = reverseStringMap(relatedPccRuleIds)
		logger.PolicyAuthorizationLog.Debugw("relatedPccRuleIds", "value", relatedPccRuleIds)
		logger.PolicyAuthorizationLog.Debugw("PccRuleIdMapToCompId", "value", data.PccRuleIdMapToCompId)
	}

	evsNotif := models.EventsNotification{}
	// Set Event Subsciption related Data
	if len(eventSubs) > 0 {
		data.Events = eventSubs
		data.EventUri = ascReqData.Get().EvSubsc.GetNotifUri()
		logger.PolicyAuthorizationLog.Debugf("registered Evt Sub for App Session ID: %s-NotifUri:[%s]", appSessID, data.EventUri)
		if _, exist := eventSubs[models.AFEVENTPCF_PLMN_CHG]; exist {
			afNotif := models.AfEventNotification{
				Event: models.AFEVENTPCF_PLMN_CHG,
			}
			evsNotif.EvNotifs = append(evsNotif.EvNotifs, afNotif)
			plmnID := smPolicy.PolicyContext.ServingNetwork
			if plmnID != nil {
				evsNotif.PlmnId = models.NewPlmnIdNid(plmnID.Mcc, plmnID.Mnc)
				logger.PolicyAuthorizationLog.Debugf("PLMN ID set in Event Notification: %s-%s", plmnID.Mcc, plmnID.Mnc)
			}
		}
		if _, exist := eventSubs[models.AFEVENTPCF_ACCESS_TYPE_CHANGE]; exist {
			afNotif := models.AfEventNotification{
				Event: models.AFEVENTPCF_ACCESS_TYPE_CHANGE,
			}
			evsNotif.EvNotifs = append(evsNotif.EvNotifs, afNotif)
			evsNotif.AccessType = smPolicy.PolicyContext.AccessType
			evsNotif.RatType = smPolicy.PolicyContext.RatType
		}
		logger.PolicyAuthorizationLog.Debugf("AccessType and RatType set for ACCESS_TYPE_CHANGE")
	}
	if evsNotif.EvNotifs == nil {
		appSessCtx.EvsNotif = nil
		logger.PolicyAuthorizationLog.Debugln("no event notifications to include in App Session Context")
	} else {
		appSessCtx.SetEvsNotif(evsNotif)
	}
	pcfSelf.AppSessionPool.Store(appSessID, &data)
	locationHeader := util.GetResourceUri(models.SERVICENAME_NPCF_POLICYAUTHORIZATION, appSessID)
	logger.PolicyAuthorizationLog.Infof("app session Id[%s] Create", appSessID)

	// Send Notification to SMF
	if updateSMpolicy {
		filteredDecision := buildRelatedSmPolicyDecision(smPolicy.PolicyDecision, relatedPccRuleIds)
		smPolicyID := fmt.Sprintf("%s-%d", ue.Supi, smPolicy.PolicyContext.PduSessionId)
		notification := models.NewSmPolicyNotification()
		notification.SetResourceUri(util.GetResourceUri(models.SERVICENAME_NPCF_SMPOLICYCONTROL, smPolicyID))
		if filteredDecision != nil {
			notification.SetSmPolicyDecision(*filteredDecision)
		}
		logger.PolicyAuthorizationLog.Debugw("smPolicyDecision data", "decision", filteredDecision)
		notifyevent.DispatchSendSMPolicyUpdateNotifyEvent(smPolicy.PolicyContext.NotificationUri, notification)
	}
	return appSessCtx, locationHeader, nil
}

func handleCombinedMediaSubComponents(
	smPolicy *pcfContext.UeSmPolicyData,
	medComp *models.MediaComponent,
	medSubComps []models.MediaSubComponent,
	var5qi int32,
	flowInfos []models.FlowInformation,
) (*models.PccRule, *models.ProblemDetails) {
	/* //Below section used for debug purpose
	// Print all existing PCC Rule IDs before creating new ones
	for id, rule := range smPolicy.PolicyDecision.PccRules {
		logger.PolicyAuthorizationLog.Debugf("existing PCC Rule ID: [%s]", id)

		// Print FlowDescriptions so you can identify IMS vs Internet
		for _, fi := range rule.FlowInfos {
			logger.PolicyAuthorizationLog.Debugf("flowDescription: %s", fi.GetFlowDescription())
		}

		// Print Qos IDs linked to this PCC Rule
		if len(rule.RefQosData) > 0 {
			if smPolicy.PolicyDecision.QosDecs == nil {
				logger.PolicyAuthorizationLog.Warnf("  QosDecs is nil; cannot resolve RefQosData for PCC Rule [%s]", id)
			} else {
				for _, qosRef := range rule.RefQosData {
					qosData, ok := (*smPolicy.PolicyDecision.QosDecs)[qosRef]
					if ok {
						logger.PolicyAuthorizationLog.Debugf("  QosData ID: [%s]", qosData.GetQosId())
					} else {
						logger.PolicyAuthorizationLog.Warnf("  QosData reference [%s] not found", qosRef)
					}
				}
			}
		}
	}
	*/

	// Step 1: Try to find an existing PCC Rule that matches the given FlowInfos
	_, existingPccRule, found := util.GetPccRuleByFlowInfos(smPolicy.PolicyDecision.PccRules, flowInfos)
	var pccRule *models.PccRule
	// ----------------------------------------------------------------
	// Step 2: If no existing PCC Rule found, create a new one
	// ----------------------------------------------------------------
	if !found {
		logger.PolicyAuthorizationLog.Infof("no existing PCC Rule found for combined FlowInfos. Creating new PCC Rule.")
		// Ensure PCC Rule ID generator is ahead of any existing PCC Rule ID
		maxExisting := getMaxPccRuleIdNum(smPolicy.PolicyDecision.PccRules)
		if smPolicy.PccRuleIdGenarator <= maxExisting {
			smPolicy.PccRuleIdGenarator = maxExisting + 1
		}
		// Determine max precedence among existing PCC Rules
		maxPrecedence := getMaxPrecedence(smPolicy.PolicyDecision.GetPccRules())
		// Create new PCC Rule (TS 29.214: QoS and PCC Rule handling)
		pccRule = util.CreatePccRule(smPolicy.PccRuleIdGenarator, maxPrecedence+1, nil, "")
		logger.PolicyAuthorizationLog.Infof("created new PCC Rule ID [%s]", pccRule.GetPccRuleId())
		qosData := util.CreateQosData(smPolicy.PccRuleIdGenarator, var5qi, 8)
		qosData.Arp.SetPreemptCap(models.PREEMPTIONCAPABILITY_MAY_PREEMPT)
		qosData.Arp.SetPreemptVuln(models.PREEMPTIONVULNERABILITY_NOT_PREEMPTABLE)
		logger.PolicyAuthorizationLog.Infof("created QosData ID [%s] (5QI=%d)", qosData.GetQosId(), var5qi)

		// If var5qi <= 4 (GBR flows), update QoS according to MediaSubComponents
		if var5qi <= 4 {
			var anyUL, anyDL bool
			for _, medSubComp := range medSubComps {
				if medSubComp.GetFStatus() == models.FLOWSTATUS_REMOVED {
					continue
				}
				var ul, dl bool
				qosData, ul, dl = updateQosInMedSubComp(&qosData, medComp, &medSubComp)
				anyUL = anyUL || ul
				anyDL = anyDL || dl
			}
			if problemDetails := modifyRemainBitRate(smPolicy, &qosData, anyUL, anyDL); problemDetails != nil {
				return nil, problemDetails
			}
		}

		// Assign Packet Filter IDs to FlowInfos and map them to PCC Rule
		for i := range flowInfos {
			flowInfos[i].SetPackFiltId(util.GetPackFiltId(smPolicy.PackFiltIdGenarator))
			smPolicy.PackFiltMapToPccRuleId[flowInfos[i].GetPackFiltId()] = pccRule.GetPccRuleId()
			logger.PolicyAuthorizationLog.Debugf("assigned PackFiltId [%s] to PCC Rule ID [%s]", flowInfos[i].GetPackFiltId(), pccRule.GetPccRuleId())
			smPolicy.PackFiltIdGenarator++
		}
		pccRule.SetFlowInfos(flowInfos)
		flowStatus := medComp.GetFStatus()
		for _, sc := range medSubComps {
			st := sc.GetFStatus()
			if st == "" {
				continue
			}
			flowStatus = st
			if st != models.FLOWSTATUS_REMOVED {
				break
			}
		}
		tcData := util.CreateTcData(smPolicy.PccRuleIdGenarator, "", flowStatus)
		util.SetPccRuleRelatedData(smPolicy.PolicyDecision, pccRule, tcData, &qosData, nil, nil)
		smPolicy.PccRuleIdGenarator++
		logger.PolicyAuthorizationLog.Debugf("pcc Rule ID [%s]", pccRule.GetPccRuleId())
	} else {
		// ----------------------------------------------------------------
		// Step 3 : Existing PCC Rule found, merge new flows and update if needed
		// ----------------------------------------------------------------
		pccRule = &existingPccRule
		logger.PolicyAuthorizationLog.Infof("found existing PCC Rule ID [%s]", pccRule.GetPccRuleId())

		if pccRule.HasRefQosData() && len(pccRule.GetRefQosData()) > 0 {
			if smPolicy.PolicyDecision.QosDecs == nil {
				logger.PolicyAuthorizationLog.Warnf("existing PCC Rule [%s] has RefQosData but QosDecs is nil", pccRule.GetPccRuleId())
			} else {
				for _, qosRef := range pccRule.GetRefQosData() {
					if qosData, ok := (*smPolicy.PolicyDecision.QosDecs)[qosRef]; ok {
						logger.PolicyAuthorizationLog.Debugf("existing PCC Rule [%s] has QosData ID [%s]",
							pccRule.GetPccRuleId(), qosData.GetQosId())
					} else {
						logger.PolicyAuthorizationLog.Warnf("existing PCC Rule [%s] has RefQosData [%s] but not found in QosDecs",
							pccRule.GetPccRuleId(), qosRef)
					}
				}
			}
		} else {
			logger.PolicyAuthorizationLog.Infof("existing PCC Rule [%s] has no QosData references", pccRule.GetPccRuleId())
		}

		// Merge new flows (FlowInfos) into the existing PCC Rule if not already present
		for _, nf := range flowInfos {
			found := false
			for _, ef := range pccRule.GetFlowInfos() {
				if ef.GetFlowDescription() == nf.GetFlowDescription() {
					found = true
					break
				}
			}
			if !found {
				nf.SetPackFiltId(util.GetPackFiltId(smPolicy.PackFiltIdGenarator))
				smPolicy.PackFiltMapToPccRuleId[nf.GetPackFiltId()] = pccRule.GetPccRuleId()
				smPolicy.PackFiltIdGenarator++
				pccRule.SetFlowInfos(append(pccRule.GetFlowInfos(), nf))
			}
		}
	}

	smPolicy.PolicyDecision.GetPccRules()[pccRule.GetPccRuleId()] = *pccRule
	logger.PolicyAuthorizationLog.Debugf("pcc Rule ID [%s] stored successfully in PolicyDecision", pccRule.GetPccRuleId())
	logger.PolicyAuthorizationLog.Debugf("final PCC Rule Snapshot for ID [%s]:", pccRule.GetPccRuleId())
	logger.PolicyAuthorizationLog.Debugf("Precedence: %d", pccRule.GetPrecedence())
	for _, fi := range pccRule.GetFlowInfos() {
		logger.PolicyAuthorizationLog.Debugf("FlowDescription: %s, PackFiltId: %s", fi.GetFlowDescription(), fi.GetPackFiltId())
	}
	logger.PolicyAuthorizationLog.Debugf("RefQosData:")
	for _, qosRef := range pccRule.GetRefQosData() {
		qosData, ok := smPolicy.PolicyDecision.GetQosDecs()[qosRef]
		if ok {
			logger.PolicyAuthorizationLog.Debugf("QosId: %s, 5QI: %d", qosData.GetQosId(), qosData.GetVar5qi())
		} else {
			logger.PolicyAuthorizationLog.Warnf("    QosData reference [%s] not found", qosRef)
		}
	}
	logger.PolicyAuthorizationLog.Debugw("pcc rule full snapshot", "pccRuleId", pccRule.GetPccRuleId(), "pccRule", pccRule)
	return pccRule, nil
}

func buildRelatedSmPolicyDecision(
	policyDecision *models.SmPolicyDecision,
	relatedPccRuleIds map[string]string,
) *models.SmPolicyDecision {
	if policyDecision == nil || len(relatedPccRuleIds) == 0 {
		return policyDecision
	}

	filteredDecision := *policyDecision
	pccRules := make(map[string]models.PccRule)
	qosDecs := make(map[string]models.QosData)
	traffContDecs := make(map[string]models.TrafficControlData)
	chgDecs := make(map[string]models.ChargingData)
	umDecs := make(map[string]models.UsageMonitoringData)

	for _, pccRuleID := range relatedPccRuleIds {
		pccRule, ok := policyDecision.GetPccRules()[pccRuleID]
		if !ok {
			continue
		}
		pccRules[pccRuleID] = pccRule

		for _, qosID := range pccRule.GetRefQosData() {
			if qos, ok := policyDecision.GetQosDecs()[qosID]; ok {
				qosDecs[qosID] = qos
			}
		}
		for _, tcID := range pccRule.GetRefTcData() {
			if tc, ok := policyDecision.GetTraffContDecs()[tcID]; ok {
				traffContDecs[tcID] = tc
			}
		}
		for _, chgID := range pccRule.GetRefChgData() {
			if chg, ok := policyDecision.GetChgDecs()[chgID]; ok {
				chgDecs[chgID] = chg
			}
		}
		for _, umID := range pccRule.GetRefUmData() {
			if um, ok := policyDecision.GetUmDecs()[umID]; ok {
				umDecs[umID] = um
			}
		}
	}

	filteredDecision.SetPccRules(pccRules)
	if len(qosDecs) > 0 {
		filteredDecision.SetQosDecs(qosDecs)
	} else {
		filteredDecision.QosDecs = nil
	}
	if len(traffContDecs) > 0 {
		filteredDecision.SetTraffContDecs(traffContDecs)
	} else {
		filteredDecision.TraffContDecs = nil
	}
	if len(chgDecs) > 0 {
		filteredDecision.SetChgDecs(chgDecs)
	} else {
		filteredDecision.ChgDecs = nil
	}
	if len(umDecs) > 0 {
		filteredDecision.SetUmDecs(umDecs)
	} else {
		filteredDecision.UmDecs = nil
	}

	return &filteredDecision
}

// HandleDeleteAppSession - Deletes an existing Individual Application Session Context
func HandleDeleteAppSessionContext(request *httpwrapper.Request) *httpwrapper.Response {
	eventsSubscReqData := request.Body.(*models.EventsSubscReqData)
	appSessID := request.Params["appSessionId"]
	logger.PolicyAuthorizationLog.Infof("handle Del AppSessions, AppSessionId[%s]", appSessID)

	problemDetails := DeleteAppSessionContextProcedure(appSessID, eventsSubscReqData)
	if problemDetails == nil {
		stats.IncrementPcfPolicyAuthorizationStats("delete", "application_sessions", "SUCCESS")
		return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
	}
	stats.IncrementPcfPolicyAuthorizationStats("delete", "application_sessions", "FAILURE")
	return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
}

func DeleteAppSessionContextProcedure(appSessID string,
	eventsSubscReqData *models.EventsSubscReqData,
) *models.ProblemDetails {
	pcfSelf := pcfContext.PCF_Self()
	var appSession *pcfContext.AppSessionData
	if val, ok := pcfSelf.AppSessionPool.Load(appSessID); ok {
		appSession = val.(*pcfContext.AppSessionData)
	}
	if appSession == nil {
		problemDetail := util.GetProblemDetail("can't find app session", util.APPLICATION_SESSION_CONTEXT_NOT_FOUND)
		return problemDetail
	}
	if eventsSubscReqData != nil {
		logger.PolicyAuthorizationLog.Warnln("delete AppSessions does not support with Event Subscription")
	}
	// Remove related pcc rule resource
	smPolicy := appSession.SmPolicyData
	for _, pccRuleID := range appSession.RelatedPccRuleIds {
		if err := smPolicy.RemovePccRule(pccRuleID, nil); err != nil {
			logger.PolicyAuthorizationLog.Warnln(err.Error())
		}
	}

	smPolicy.RemoveAppSession(appSessID)

	logger.PolicyAuthorizationLog.Infof("app session Id[%s] Del", appSessID)

	pcfSelf.AppSessionPool.Delete(appSessID)

	smPolicy.ArrangeExistEventSubscription()

	// Notify SMF About Pcc Rule moval
	smPolicyID := fmt.Sprintf("%s-%d", smPolicy.PcfUe.Supi, smPolicy.PolicyContext.GetPduSessionId())
	notification := models.NewSmPolicyNotification()
	notification.SetResourceUri(util.GetResourceUri(models.SERVICENAME_NPCF_SMPOLICYCONTROL, smPolicyID))
	notification.SetSmPolicyDecision(*smPolicy.PolicyDecision)
	notifyevent.DispatchSendSMPolicyUpdateNotifyEvent(smPolicy.PolicyContext.GetNotificationUri(), notification)
	logger.PolicyAuthorizationLog.Debugf("send SM Policy[%s] Update Notification", smPolicyID)
	return nil
}

// HandleGetAppSession - Reads an existing Individual Application Session Context
func HandleGetAppSessionContext(request *httpwrapper.Request) *httpwrapper.Response {
	appSessID := request.Params["appSessionId"]
	logger.PolicyAuthorizationLog.Infof("handle Get AppSessions, AppSessionId[%s]", appSessID)

	problemDetails, response := GetAppSessionContextProcedure(appSessID)
	if problemDetails == nil {
		stats.IncrementPcfPolicyAuthorizationStats("get", "application_sessions", "SUCCESS")
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	}
	stats.IncrementPcfPolicyAuthorizationStats("get", "application_sessions", "FAILURE")
	return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
}

func GetAppSessionContextProcedure(appSessID string) (*models.ProblemDetails, *models.AppSessionContext) {
	pcfSelf := pcfContext.PCF_Self()

	var appSession *pcfContext.AppSessionData
	if val, ok := pcfSelf.AppSessionPool.Load(appSessID); ok {
		appSession = val.(*pcfContext.AppSessionData)
	}
	if appSession == nil {
		problemDetail := util.GetProblemDetail("can't find app session", util.APPLICATION_SESSION_CONTEXT_NOT_FOUND)
		return problemDetail, nil
	}
	logger.PolicyAuthorizationLog.Debugf("app Session Id[%s] Get", appSessID)
	return nil, appSession.AppSessionContext
}

// HandleModAppSession - Modifies an existing Individual Application Session Context
func HandleModAppSessionContext(request *httpwrapper.Request) *httpwrapper.Response {
	appSessID := request.Params["appSessionId"]
	ascUpdateData := request.Body.(models.AppSessionContextUpdateData)
	logger.PolicyAuthorizationLog.Infof("handle Modify AppSessions, AppSessionId[%s]", appSessID)

	problemDetails, response := ModAppSessionContextProcedure(appSessID, ascUpdateData)
	if problemDetails == nil {
		stats.IncrementPcfPolicyAuthorizationStats("update", "application_sessions", "SUCCESS")
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	}
	stats.IncrementPcfPolicyAuthorizationStats("update", "application_sessions", "FAILURE")
	return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
}

func ModAppSessionContextProcedure(appSessID string,
	ascUpdateData models.AppSessionContextUpdateData,
) (*models.ProblemDetails, *models.AppSessionContext) {
	pcfSelf := pcfContext.PCF_Self()
	var appSession *pcfContext.AppSessionData
	if val, ok := pcfSelf.AppSessionPool.Load(appSessID); ok {
		appSession = val.(*pcfContext.AppSessionData)
	}
	if appSession == nil {
		problemDetail := util.GetProblemDetail("cannot find app session", util.APPLICATION_SESSION_CONTEXT_NOT_FOUND)
		return problemDetail, nil
	}
	appSessCtx := appSession.AppSessionContext
	if ascUpdateData.GetBdtRefId() != "" {
		appSessCtx.AscReqData.Get().SetBdtRefId(ascUpdateData.GetBdtRefId())
		if err := handleBDTPolicyInd(pcfSelf, appSessCtx); err != nil {
			problemDetail := util.GetProblemDetail(err.Error(), util.ERROR_REQUEST_PARAMETERS)
			return problemDetail, nil
		}
		logger.PolicyAuthorizationLog.Debugf("app session Id[%s] Updated", appSessID)
		return nil, appSessCtx
	}
	smPolicy := appSession.SmPolicyData
	if smPolicy == nil {
		problemDetail := util.GetProblemDetail("cannot find related PDU Session", util.REQUESTED_SERVICE_NOT_AUTHORIZED)
		return problemDetail, nil
	}
	// InfluenceOnTrafficRouting = 1 in 29514 &  Traffic Steering Control support = 1 in 29512
	traffRoutSupp := util.CheckSuppFeat(appSessCtx.AscRespData.GetSuppFeat(),
		1) && util.CheckSuppFeat(smPolicy.PolicyDecision.GetSuppFeat(), 1)
	relatedPccRuleIds := make(map[string]string)
	// Event Subscription
	eventSubs := make(map[models.AfEventPcf]models.AfNotifMethod)
	updateSMpolicy := false

	if ascUpdateData.HasMedComponents() {
		maxPrecedence := getMaxPrecedence(smPolicy.PolicyDecision.PccRules)
		for compN, medCompRm := range ascUpdateData.GetMedComponents() {
			removeMediaComp(appSession, compN)
			if reflect.ValueOf(medCompRm).IsZero() {
				// media component is null => removal only, nothing to reinstall
				continue
			}
			medComp := transferMedCompRmToMedComp(&medCompRm)
			// modify MediaComp(remove and reinstall again)
			var pccRule *models.PccRule
			var appID string
			var routeReq *models.AfRoutingRequirement
			// TODO: use specific algorithm instead of default, details in subsclause 7.3.3 of TS 29513
			var var5qi int32 = 9
			if medComp.GetMedType() != "" {
				var5qi = util.MediaTypeTo5qiMap[medComp.GetMedType()]
			}
			if medComp.HasMedSubComps() {
				var allFlowInfos []models.FlowInformation
				var medSubCompsList []models.MediaSubComponent
				for _, medSubComp := range medComp.GetMedSubComps() {
					flowInfos, err := getFlowInfos(&medSubComp)
					if err != nil {
						problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
						return problemDetail, nil
					}
					allFlowInfos = append(allFlowInfos, flowInfos...)
					medSubCompsList = append(medSubCompsList, medSubComp)
				}
				tempPccRule, problemDetail := handleCombinedMediaSubComponents(smPolicy, medComp,
					medSubCompsList, var5qi, allFlowInfos)
				if problemDetail != nil {
					return problemDetail, nil
				}
				pccRule = tempPccRule
				for _, medSubComp := range medSubCompsList {
					key := fmt.Sprintf("%d-%d", medComp.GetMedCompN(), medSubComp.GetFNum())
					relatedPccRuleIds[key] = pccRule.GetPccRuleId()
				}
				updateSMpolicy = true
				maxPrecedence = getMaxPrecedence(smPolicy.PolicyDecision.GetPccRules())
				continue
			} else if medComp.GetAfAppId() != "" {
				// if medComp.AfAppId has value -> find pccRule by reqData.AfAppId, otherwise create a new pcc rule
				appID = medComp.GetAfAppId()
				routeReq = medComp.AfRoutReq
			} else if ascUpdateData.GetAfAppId() != "" {
				appID = ascUpdateData.GetAfAppId()
				routeReq = medComp.AfRoutReq
			} else {
				problemDetail := util.GetProblemDetail("Media Component needs flows of subComp or afAppId",
					util.REQUESTED_SERVICE_NOT_AUTHORIZED)
				return problemDetail, nil
			}

			_, existingPccRule, found := util.GetPccRuleByAfAppId(smPolicy.PolicyDecision.GetPccRules(), appID)
			if !found { // create new pcc rule
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
				pccRule = &existingPccRule
				// update qos
				var qosData models.QosData
				for _, qosID := range pccRule.GetRefQosData() {
					qosData = (*smPolicy.PolicyDecision.QosDecs)[qosID]
					if qosData.GetVar5qi() == var5qi && qosData.GetVar5qi() <= 4 {
						var ul, dl bool
						qosData, ul, dl = updateQosInMedComp((*smPolicy.PolicyDecision.QosDecs)[qosID], medComp)
						if problemDetail := modifyRemainBitRate(smPolicy, &qosData, ul, dl); problemDetail != nil {
							return problemDetail, nil
						}
						(*smPolicy.PolicyDecision.QosDecs)[qosData.QosId] = qosData
					}
				}
			}
			// Modify provisioning of traffic routing information
			if traffRoutSupp {
				pccRule = provisioningOfTrafficRoutingInfo(smPolicy, appID, routeReq, medComp.GetFStatus())
			}
			key := fmt.Sprintf("%d", medComp.GetMedCompN())
			relatedPccRuleIds[key] = pccRule.GetPccRuleId()
			updateSMpolicy = true
		}
	}

	// Update of traffic routing information
	// TODO: check ascUpdateData.AfAppId with appSessCtx.AscReqData.AfAppId (now ascUpdateData.AfAppId is empty)
	if afRoutReqRm := ascUpdateData.AfRoutReq.Get(); afRoutReqRm != nil && traffRoutSupp {
		logger.PolicyAuthorizationLog.Infof("update traffic routing info - [%+v]", ascUpdateData.AfRoutReq)
		appSessCtx.AscReqData.Get().SetAfRoutReq(transferAfRoutReqRmToAfRoutReq(*afRoutReqRm))
		// Update SmPolicyDecision
		pccRule := provisioningOfTrafficRoutingInfo(smPolicy,
			appSessCtx.AscReqData.Get().GetAfAppId(), appSessCtx.AscReqData.Get().AfRoutReq, "")
		key := fmt.Sprintf("appID-%s", *appSessCtx.AscReqData.Get().AfAppId)
		relatedPccRuleIds[key] = pccRule.GetPccRuleId()
		updateSMpolicy = true
	}

	// Merge Original PccRuleId and new
	maps.Copy(relatedPccRuleIds, appSession.RelatedPccRuleIds)

	evSubs := ascUpdateData.EvSubsc.Get()
	if evSubs != nil {
		for _, subs := range evSubs.GetEvents() {
			if subs.GetNotifMethod() == "" {
				// default value "EVENT_DETECTION"
				subs.SetNotifMethod(models.AFNOTIFMETHOD_EVENT_DETECTION)
			}
			eventSubs[subs.GetEvent()] = subs.GetNotifMethod()
			var trig models.PolicyControlRequestTrigger
			switch subs.GetEvent() {
			case models.AFEVENTPCF_ACCESS_TYPE_CHANGE:
				trig = models.POLICYCONTROLREQUESTTRIGGER_AC_TY_CH
			// case models.AFEVENTPCF_FAILED_RESOURCES_ALLOCATION:
			// 	// Subscription to Service Data Flow Deactivation
			// 	trig = models.POLICYCONTROLREQUESTTRIGGER_SUCC_RES_ALLO
			case models.AFEVENTPCF_PLMN_CHG:
				trig = models.POLICYCONTROLREQUESTTRIGGER_PLMN_CH
			case models.AFEVENTPCF_QOS_NOTIF:
				// Subscriptions to Service Data Flow QoS notification control
				for _, pccRuleID := range relatedPccRuleIds {
					pccRule := smPolicy.PolicyDecision.GetPccRules()[pccRuleID]
					qosDecs := smPolicy.PolicyDecision.GetQosDecs()
					for _, qosID := range pccRule.GetRefQosData() {
						qosData, ok := qosDecs[qosID]
						if !ok {
							continue
						}
						qosData.SetQnc(true)
						qosDecs[qosID] = qosData
					}
				}
				trig = models.POLICYCONTROLREQUESTTRIGGER_QOS_NOTIF
			case models.AFEVENTPCF_SUCCESSFUL_RESOURCES_ALLOCATION:
				// Subscription to resources allocation outcome
				trig = models.POLICYCONTROLREQUESTTRIGGER_SUCC_RES_ALLO
			case models.AFEVENTPCF_USAGE_REPORT:
				trig = models.POLICYCONTROLREQUESTTRIGGER_US_RE
			default:
				logger.PolicyAuthorizationLog.Warnln("AF Event is unknown")
				continue
			}
			if !util.CheckPolicyControlReqTrig(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, trig) {
				smPolicy.PolicyDecision.PolicyCtrlReqTriggers = append(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, trig)
				updateSMpolicy = true
			}
		}
		// update Context
		if !appSessCtx.AscReqData.Get().HasEvSubsc() {
			appSessCtx.AscReqData.Get().EvSubsc = models.NewEventsSubscReqDataWithDefaults()
		}
		appSessCtx.AscReqData.Get().EvSubsc.Events = ascUpdateData.EvSubsc.Get().GetEvents()
		if ascUpdateData.EvSubsc.Get().GetNotifUri() != "" {
			appSessCtx.AscReqData.Get().EvSubsc.SetNotifUri(ascUpdateData.EvSubsc.Get().GetNotifUri())
			appSession.EventUri = ascUpdateData.EvSubsc.Get().GetNotifUri()
		}
		if usgThresRm := ascUpdateData.EvSubsc.Get().UsgThres.Get(); usgThresRm != nil {
			appSessCtx.AscReqData.Get().EvSubsc.SetUsgThres(*threshRmToThresh(usgThresRm))
		}
	} else {
		// remove eventSubs
		appSession.Events = nil
		appSession.EventUri = ""
		appSessCtx.AscReqData.Get().EvSubsc = nil
	}

	// Moification provisioning of sponsored connectivity information
	if ascUpdateData.GetAspId() != "" && ascUpdateData.GetSponId() != "" {
		umID := util.GetUmId(ascUpdateData.GetAspId(), ascUpdateData.GetSponId())
		var umData *models.UsageMonitoringData
		tempUmData, err := extractUmData(umID, eventSubs, threshRmToThresh(ascUpdateData.EvSubsc.Get().UsgThres.Get()))
		if err != nil {
			problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
			return problemDetail, nil
		}
		umData = tempUmData
		if err := handleSponsoredConnectivityInformation(smPolicy, relatedPccRuleIds, ascUpdateData.GetAspId(),
			ascUpdateData.GetSponId(), ascUpdateData.GetSponStatus(), umData, &updateSMpolicy); err != nil {
			problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
			return problemDetail, nil
		}
	}

	if len(relatedPccRuleIds) > 0 {
		appSession.RelatedPccRuleIds = relatedPccRuleIds
		appSession.PccRuleIdMapToCompId = reverseStringMap(relatedPccRuleIds)
	}
	appSessCtx.EvsNotif = models.NewEventsNotificationWithDefaults()
	// Set Event Subsciption related Data
	if len(eventSubs) > 0 {
		appSession.Events = eventSubs
		if _, exist := eventSubs[models.AFEVENTPCF_PLMN_CHG]; exist {
			afNotif := models.AfEventNotification{
				Event: models.AFEVENTPCF_PLMN_CHG,
			}
			appSessCtx.EvsNotif.EvNotifs = append(appSessCtx.EvsNotif.EvNotifs, afNotif)
			plmnID := smPolicy.PolicyContext.ServingNetwork
			if plmnID != nil {
				appSessCtx.EvsNotif.PlmnId = models.NewPlmnIdNid(plmnID.Mcc, plmnID.Mnc)
			}
		}
		if _, exist := eventSubs[models.AFEVENTPCF_ACCESS_TYPE_CHANGE]; exist {
			afNotif := models.AfEventNotification{
				Event: models.AFEVENTPCF_ACCESS_TYPE_CHANGE,
			}
			appSessCtx.EvsNotif.EvNotifs = append(appSessCtx.EvsNotif.EvNotifs, afNotif)
			appSessCtx.EvsNotif.AccessType = smPolicy.PolicyContext.AccessType
			appSessCtx.EvsNotif.RatType = smPolicy.PolicyContext.RatType
		}
	}
	if len(appSessCtx.EvsNotif.GetEvNotifs()) == 0 {
		appSessCtx.EvsNotif = nil
	}

	// TODO: MPS Service
	logger.PolicyAuthorizationLog.Debugf("app session Id[%s] Updated", appSessID)

	smPolicy.ArrangeExistEventSubscription()

	// Send Notification to SMF
	if updateSMpolicy {
		smPolicyID := fmt.Sprintf("%s-%d", smPolicy.PcfUe.Supi, smPolicy.PolicyContext.PduSessionId)
		notification := models.NewSmPolicyNotification()
		{
			notification.SetResourceUri(util.GetResourceUri(models.SERVICENAME_NPCF_SMPOLICYCONTROL, smPolicyID))
			notification.SetSmPolicyDecision(*smPolicy.PolicyDecision)
		}
		notifyevent.DispatchSendSMPolicyUpdateNotifyEvent(smPolicy.PolicyContext.GetNotificationUri(), notification)
		logger.PolicyAuthorizationLog.Debugf("send SM Policy[%s] Update Notification", smPolicyID)
	}
	return nil, appSessCtx
}

// HandleDeleteEventsSubsc - deletes the Events Subscription subresource
func HandleDeleteEventsSubscContext(request *httpwrapper.Request) *httpwrapper.Response {
	appSessID := request.Params["appSessID"]
	logger.PolicyAuthorizationLog.Debugf("handle Del AppSessions Events Subsc, AppSessionId[%s]", appSessID)

	problemDetails := DeleteEventsSubscContextProcedure(appSessID)
	if problemDetails == nil {
		stats.IncrementPcfPolicyAuthorizationStats("delete", "events_subscriptions", "SUCCESS")
		return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
	} else {
		stats.IncrementPcfPolicyAuthorizationStats("delete", "events_subscriptions", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
}

func DeleteEventsSubscContextProcedure(appSessID string) *models.ProblemDetails {
	pcfSelf := pcfContext.PCF_Self()
	var appSession *pcfContext.AppSessionData
	if val, ok := pcfSelf.AppSessionPool.Load(appSessID); ok {
		appSession = val.(*pcfContext.AppSessionData)
	}
	if appSession == nil {
		problemDetail := util.GetProblemDetail("can't find app session", util.APPLICATION_SESSION_CONTEXT_NOT_FOUND)
		return problemDetail
	}
	appSession.Events = nil
	appSession.EventUri = ""
	appSession.AppSessionContext.EvsNotif = nil
	appSession.AppSessionContext.AscReqData.Get().EvSubsc = nil

	// changed := appSession.SmPolicyData.ArrangeExistEventSubscription()

	logger.PolicyAuthorizationLog.Debugf("app session Id[%s] Del Events Subsc success", appSessID)

	smPolicy := appSession.SmPolicyData
	// Send Notification to SMF
	if changed := appSession.SmPolicyData.ArrangeExistEventSubscription(); changed {
		smPolicyID := fmt.Sprintf("%s-%d", smPolicy.PcfUe.Supi, smPolicy.PolicyContext.PduSessionId)
		notification := models.NewSmPolicyNotification()
		notification.SetResourceUri(util.GetResourceUri(models.SERVICENAME_NPCF_SMPOLICYCONTROL, smPolicyID))
		notification.SetSmPolicyDecision(*smPolicy.PolicyDecision)
		notifyevent.DispatchSendSMPolicyUpdateNotifyEvent(smPolicy.PolicyContext.GetNotificationUri(), notification)
		logger.PolicyAuthorizationLog.Debugf("send SM Policy[%s] Update Notification", smPolicyID)
	}
	return nil
}

// HandleUpdateEventsSubsc - creates or modifies an Events Subscription subresource
func HandleUpdateEventsSubscContext(request *httpwrapper.Request) *httpwrapper.Response {
	EventsSubscReqData := request.Body.(models.EventsSubscReqData)
	appSessID := request.Params["appSessID"]
	logger.PolicyAuthorizationLog.Debugf("handle Put AppSessions Events Subsc, AppSessionId[%s]", appSessID)

	response, locationHeader, status, problemDetails := UpdateEventsSubscContextProcedure(appSessID, EventsSubscReqData)
	if problemDetails != nil {
		stats.IncrementPcfPolicyAuthorizationStats("update", "events_subscriptions", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	} else if status == http.StatusCreated {
		stats.IncrementPcfPolicyAuthorizationStats("update", "events_subscriptions", "SUCCESS")
		headers := http.Header{
			locationHeaderKey: {locationHeader},
		}
		return httpwrapper.NewResponse(http.StatusCreated, headers, response)
	} else if status == http.StatusOK {
		stats.IncrementPcfPolicyAuthorizationStats("update", "events_subscriptions", "SUCCESS")
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if status == http.StatusNoContent {
		stats.IncrementPcfPolicyAuthorizationStats("update", "events_subscriptions", "SUCCESS")
		return httpwrapper.NewResponse(http.StatusNoContent, nil, response)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	stats.IncrementPcfPolicyAuthorizationStats("update", "events_subscriptions", "FAILURE")
	return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
}

func SendAppSessionEventNotification(appSession *pcfContext.AppSessionData, request models.EventsNotification) {
	logger.PolicyAuthorizationLog.Debugln("send App Session Event Notification")
	if appSession == nil {
		logger.PolicyAuthorizationLog.Warnln("send App Session Event Notification Error[appSession is nil]")
		return
	}
	uri := appSession.EventUri
	if uri != "" {
		request.EvSubsUri = fmt.Sprintf("%s/events-subscription",
			util.GetResourceUri(models.SERVICENAME_NPCF_POLICYAUTHORIZATION, appSession.AppSessionId))
		postAppSessionCallbackJSON(uri, request, "App Session Event Notification")
	}
}

func UpdateEventsSubscContextProcedure(appSessID string, eventsSubscReqData models.EventsSubscReqData) (
	*models.EventsSubscPutData, string, int, *models.ProblemDetails,
) {
	pcfSelf := pcfContext.PCF_Self()

	var appSession *pcfContext.AppSessionData
	if val, ok := pcfSelf.AppSessionPool.Load(appSessID); ok {
		appSession = val.(*pcfContext.AppSessionData)
	}
	if appSession == nil {
		problemDetail := util.GetProblemDetail("can't find app session", util.APPLICATION_SESSION_CONTEXT_NOT_FOUND)
		return nil, "", int(problemDetail.GetStatus()), problemDetail
	}
	smPolicy := appSession.SmPolicyData
	eventSubs := make(map[models.AfEventPcf]models.AfNotifMethod)

	updataSmPolicy := false
	created := appSession.Events == nil

	for _, subs := range eventsSubscReqData.GetEvents() {
		if subs.GetNotifMethod() == "" {
			// default value "EVENT_DETECTION"
			notifMethod := models.AFNOTIFMETHOD_EVENT_DETECTION
			subs.NotifMethod = &notifMethod
		}
		eventSubs[subs.Event] = subs.GetNotifMethod()
		var trig models.PolicyControlRequestTrigger
		switch subs.Event {
		case models.AFEVENTPCF_ACCESS_TYPE_CHANGE:
			trig = models.POLICYCONTROLREQUESTTRIGGER_AC_TY_CH
		// case models.AFEVENTPCF_FAILED_RESOURCES_ALLOCATION:
		// 	// Subscription to Service Data Flow Deactivation
		// 	trig = models.POLICYCONTROLREQUESTTRIGGER_SUCC_RES_ALLO
		case models.AFEVENTPCF_PLMN_CHG:
			trig = models.POLICYCONTROLREQUESTTRIGGER_PLMN_CH
		case models.AFEVENTPCF_QOS_NOTIF:
			// Subscriptions to Service Data Flow QoS notification control
			for _, pccRuleID := range appSession.RelatedPccRuleIds {
				pccRule := smPolicy.PolicyDecision.GetPccRules()[pccRuleID]
				qosDecs := smPolicy.PolicyDecision.GetQosDecs()
				for _, qosID := range pccRule.GetRefQosData() {
					qosData, ok := qosDecs[qosID]
					if !ok {
						continue
					}
					qosData.SetQnc(true)
					qosDecs[qosID] = qosData
				}
			}
			trig = models.POLICYCONTROLREQUESTTRIGGER_QOS_NOTIF
		case models.AFEVENTPCF_SUCCESSFUL_RESOURCES_ALLOCATION:
			// Subscription to resources allocation outcome
			trig = models.POLICYCONTROLREQUESTTRIGGER_SUCC_RES_ALLO
		case models.AFEVENTPCF_USAGE_REPORT:
			trig = models.POLICYCONTROLREQUESTTRIGGER_US_RE
		default:
			logger.PolicyAuthorizationLog.Warnln("AF Event is unknown")
			continue
		}
		if !util.CheckPolicyControlReqTrig(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, trig) {
			smPolicy.PolicyDecision.PolicyCtrlReqTriggers = append(smPolicy.PolicyDecision.PolicyCtrlReqTriggers, trig)
			updataSmPolicy = true
		}
	}
	appSessCtx := appSession.AppSessionContext
	// update Context
	if !appSessCtx.AscReqData.Get().HasEvSubsc() {
		appSessCtx.AscReqData.Get().EvSubsc = new(models.EventsSubscReqData)
	}
	appSessCtx.AscReqData.Get().EvSubsc.SetEvents(eventsSubscReqData.GetEvents())
	if eventsSubscReqData.HasUsgThres() {
		appSessCtx.AscReqData.Get().EvSubsc.SetUsgThres(eventsSubscReqData.GetUsgThres())
	} else {
		appSessCtx.AscReqData.Get().EvSubsc.UsgThres = nil
	}
	if eventsSubscReqData.GetNotifUri() != "" {
		appSessCtx.AscReqData.Get().EvSubsc.SetNotifUri(eventsSubscReqData.GetNotifUri())
	} else {
		appSessCtx.AscReqData.Get().EvSubsc.NotifUri = nil
	}
	appSessCtx.EvsNotif = nil
	// update app Session
	appSession.EventUri = eventsSubscReqData.GetNotifUri()
	appSession.Events = eventSubs

	resp := models.EventsSubscPutData{
		EventsSubscReqData: &eventsSubscReqData,
	}
	appSessCtx.EvsNotif = models.NewEventsNotificationWithDefaults()
	appSessCtx.EvsNotif.SetEvSubsUri(eventsSubscReqData.GetNotifUri())
	// Set Event Subsciption related Data
	if len(eventSubs) > 0 {
		if _, exist := eventSubs[models.AFEVENTPCF_PLMN_CHG]; exist {
			afNotif := models.AfEventNotification{
				Event: models.AFEVENTPCF_PLMN_CHG,
			}
			appSessCtx.EvsNotif.EvNotifs = append(appSessCtx.EvsNotif.EvNotifs, afNotif)
			plmnID := smPolicy.PolicyContext.ServingNetwork
			if plmnID != nil {
				appSessCtx.EvsNotif.PlmnId = models.NewPlmnIdNid(plmnID.Mcc, plmnID.Mnc)
			}
		}
		if _, exist := eventSubs[models.AFEVENTPCF_ACCESS_TYPE_CHANGE]; exist {
			afNotif := models.AfEventNotification{
				Event: models.AFEVENTPCF_ACCESS_TYPE_CHANGE,
			}
			appSessCtx.EvsNotif.EvNotifs = append(appSessCtx.EvsNotif.EvNotifs, afNotif)
			appSessCtx.EvsNotif.SetAccessType(smPolicy.PolicyContext.GetAccessType())
			appSessCtx.EvsNotif.SetRatType(smPolicy.PolicyContext.GetRatType())
		}
	}
	if len(appSessCtx.EvsNotif.GetEvNotifs()) == 0 {
		appSessCtx.EvsNotif = nil
	}

	resp.EventsNotification = appSessCtx.EvsNotif

	changed := appSession.SmPolicyData.ArrangeExistEventSubscription()

	// Send Notification to SMF
	if updataSmPolicy || changed {
		smPolicyID := fmt.Sprintf("%s-%d", smPolicy.PcfUe.Supi, smPolicy.PolicyContext.PduSessionId)
		notification := models.NewSmPolicyNotification()
		notification.SetResourceUri(util.GetResourceUri(models.SERVICENAME_NPCF_SMPOLICYCONTROL, smPolicyID))
		notification.SetSmPolicyDecision(*smPolicy.PolicyDecision)
		notifyevent.DispatchSendSMPolicyUpdateNotifyEvent(smPolicy.PolicyContext.NotificationUri, notification)
		logger.PolicyAuthorizationLog.Debugf("send SM Policy[%s] Update Notification", smPolicyID)
	}
	if created {
		locationHeader := fmt.Sprintf("%s/events-subscription",
			util.GetResourceUri(models.SERVICENAME_NPCF_POLICYAUTHORIZATION, appSessID))
		logger.PolicyAuthorizationLog.Debugf("app session Id[%s] Create Subscription", appSessID)
		return &resp, locationHeader, http.StatusCreated, nil
	}
	if resp.EventsNotification != nil {
		logger.PolicyAuthorizationLog.Debugf("app session Id[%s] Modify Subscription", appSessID)
		return &resp, "", http.StatusOK, nil
	}
	logger.PolicyAuthorizationLog.Debugf("app session Id[%s] Modify Subscription", appSessID)
	return &resp, "", http.StatusNoContent, nil
}

func SendAppSessionTermination(appSession *pcfContext.AppSessionData, request models.TerminationInfo) {
	logger.PolicyAuthorizationLog.Debugln("send App Session Termination")
	if appSession == nil {
		logger.PolicyAuthorizationLog.Warnln("send App Session Termination Error[appSession is nil]")
		return
	}
	uri := appSession.AppSessionContext.AscReqData.Get().GetNotifUri()
	if uri != "" {
		request.SetResUri(util.GetResourceUri(models.SERVICENAME_NPCF_POLICYAUTHORIZATION, appSession.AppSessionId))
		postAppSessionCallbackJSON(uri, request, "App Session Termination")
	}
}

// Handle Create/ Modify Background Data Transfer Policy Indication
func handleBDTPolicyInd(pcfSelf *pcfContext.PCFContext, appSessCtx *models.AppSessionContext) error {
	req := appSessCtx.AscReqData

	var requestSuppFeat pcfContext.SupportedFeature
	if tempRequestSuppFeat, err := pcfContext.NewSupportedFeature(req.Get().GetSuppFeat()); err != nil {
		logger.PolicyAuthorizationLog.Errorln("sponsored connectivity is disabled by AF")
	} else {
		requestSuppFeat = *tempRequestSuppFeat
	}
	pcfSuppFeat := pcfSelf.PcfSuppFeats[models.SERVICENAME_NPCF_POLICYAUTHORIZATION]
	suppFeat, err := (&pcfSuppFeat).NegotiateWith(&requestSuppFeat)
	if err != nil {
		return fmt.Errorf("failed to negotiate supported features: %w", err)
	}

	respData := models.NewAppSessionContextRespData()
	respData.SetServAuthInfo(models.SERVAUTHINFO_TP_NOT_KNOWN)
	respData.SetSuppFeat(suppFeat.String())
	client := util.GetNudrClient(getDefaultUdrUri(pcfSelf))
	apiReadIndividualBdtDataRequest := client.IndividualBdtDataDocumentAPI.ReadIndividualBdtData(context.Background(), req.Get().GetBdtRefId())
	bdtData, resp, err1 := client.IndividualBdtDataDocumentAPI.ReadIndividualBdtDataExecute(apiReadIndividualBdtDataRequest)
	if err1 != nil {
		return fmt.Errorf("UDR Get BdtData error[%s]", err1.Error())
	} else if resp == nil || resp.StatusCode != http.StatusOK {
		return fmt.Errorf("UDR Get BdtData error")
	} else {
		defer func() {
			if rspCloseErr := resp.Body.Close(); rspCloseErr != nil {
				logger.PolicyAuthorizationLog.Errorf(
					"ReadIndividualBdtDataExecute response body cannot close: %+v", rspCloseErr)
			}
		}()
		if bdtData.TransPolicy.RecTimeInt.GetStartTime().After(time.Now()) {
			respData.ServAuthInfo = models.SERVAUTHINFO_TP_NOT_YET_OCURRED.Ptr()
		} else if bdtData.TransPolicy.RecTimeInt.GetStopTime().Before(time.Now()) {
			respData.ServAuthInfo = models.SERVAUTHINFO_TP_EXPIRED.Ptr()
		}
	}
	appSessCtx.SetAscRespData(*respData)
	return nil
}

// provisioning of sponsored connectivity information
func handleSponsoredConnectivityInformation(smPolicy *pcfContext.UeSmPolicyData, relatedPccRuleIds map[string]string,
	aspID, sponID string, sponStatus models.SponsoringStatus, umData *models.UsageMonitoringData,
	updateSMpolicy *bool,
) error {
	if sponStatus == models.SPONSORINGSTATUS_SPONSOR_DISABLED {
		logger.PolicyAuthorizationLog.Debugln("sponsored connectivity is disabled by AF")
		umID := util.GetUmId(aspID, sponID)
		for _, pccRuleID := range relatedPccRuleIds {
			pccRule := smPolicy.PolicyDecision.PccRules[pccRuleID]
			for _, chgID := range pccRule.GetRefChgData() {
				// disables sponsoring a service
				chgData := smPolicy.PolicyDecision.ChgDecs[chgID]
				if chgData.GetAppSvcProvId() == aspID && chgData.GetSponsorId() == sponID {
					chgData.SetSponsorId("")
					chgData.SetAppSvcProvId("")
					chgData.SetReportingLevel(models.REPORTINGLEVEL_SER_ID_LEVEL)
					smPolicy.PolicyDecision.ChgDecs[chgID] = chgData
					*updateSMpolicy = true
				}
			}
			if pccRule.HasRefUmData() {
				pccRule.RefUmData = nil
				smPolicy.PolicyDecision.PccRules[pccRuleID] = pccRule
			}
			// disable the usage monitoring
			// TODO: As a result, PCF gets the accumulated usage of the sponsored data connectivity
			delete(smPolicy.PolicyDecision.UmDecs, umID)
		}
	} else {
		if umData != nil {
			supp := util.CheckSuppFeat(smPolicy.PolicyDecision.GetSuppFeat(), 5) // UMC support = 5 in 29512
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
			if pccRule.HasRefChgData() {
				chgID := pccRule.GetRefChgData()[0]
				chgData = smPolicy.PolicyDecision.ChgDecs[chgID]
			} else {
				chgIDUsed = true
			}
			// TODO: PCF, based on operator policies, shall check whether it is required to
			// validate the sponsored connectivity data.
			// If it is required, it shall perform the authorizations based on sponsored data connectivity profiles.
			// If the authorization fails, the PCF shall send HTTP "403 Forbidden" with the "cause" attribute set to
			// "UNAUTHORIZED_SPONSORED_DATA_CONNECTIVITY"
			pccRule.SetRefChgData([]string{chgData.ChgId})
			chgData.ReportingLevel.Set(models.REPORTINGLEVEL_SPON_CON_LEVEL.Ptr())
			chgData.SetSponsorId(sponID)
			chgData.SetAppSvcProvId(aspID)
			if umData != nil {
				pccRule.SetRefUmData([]string{umData.UmId})
			}
			util.SetPccRuleRelatedData(smPolicy.PolicyDecision, &pccRule, nil, nil, &chgData, umData)
			*updateSMpolicy = true
		}
		if chgIDUsed {
			smPolicy.ChargingIdGenarator++
		}
		// TODO: handling UE is roaming in VPLMN case
	}
	return nil
}

func getMaxPrecedence(pccRules map[string]models.PccRule) (maxVaule int32) {
	maxVaule = 0
	for _, rule := range pccRules {
		if rule.GetPrecedence() > maxVaule {
			maxVaule = rule.GetPrecedence()
		}
	}
	return
}

func getMaxPccRuleIdNum(pccRules map[string]models.PccRule) int32 {
	var maxVal int32
	foundNumericID := false
	for id := range pccRules {
		n, ok := parsePccRuleID(id)
		if !ok {
			continue
		}
		foundNumericID = true
		if n > maxVal {
			maxVal = n
		}
	}
	if !foundNumericID {
		return int32(len(pccRules))
	}
	return maxVal
}

func parsePccRuleID(id string) (int32, bool) {
	if n, err := strconv.ParseInt(id, 10, 32); err == nil {
		return int32(n), true
	}

	const legacyPrefix = "PccRuleId-"
	if trimmedID, found := strings.CutPrefix(id, legacyPrefix); found {
		if n, err := strconv.ParseInt(trimmedID, 10, 32); err == nil {
			return int32(n), true
		}
	}

	return 0, false
}

/*
func getFlowInfos(comp models.MediaComponent) (flows []models.FlowInformation, err error) {
	for _, subComp := range comp.MedSubComps {
		if subComp.EthfDescs != nil {
			return nil, fmt.Errorf("Flow Description with Mac Address does not support")
		}
		fStatus := subComp.FStatus
		if subComp.FlowUsage == models.FLOWUSAGE_RTCP {
			fStatus = models.FLOWSTATUS_ENABLED
		} else if fStatus == "" {
			fStatus = comp.FStatus
		}
		if fStatus == models.FLOWSTATUS_REMOVED {
			continue
		}
		// gate control
		statusUsage := map[models.FlowDirection]bool{
			models.FLOWDIRECTION_UPLINK:   true,
			models.FLOWDIRECTION_DOWNLINK: true,
		}
		switch fStatus {
		case models.FLOWSTATUS_ENABLED_UPLINK:
			statusUsage[models.FLOWDIRECTION_DOWNLINK] = false
		case models.FLOWSTATUS_ENABLED_DOWNLINK:
			statusUsage[models.FLOWDIRECTION_UPLINK] = false
		case models.FLOWSTATUS_DISABLED:
			statusUsage[models.FLOWDIRECTION_DOWNLINK] = false
			statusUsage[models.FLOWDIRECTION_UPLINK] = false
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
	if subComp.GetFlowUsage() == models.FLOWUSAGE_RTCP {
		subComp.SetFStatus(models.FLOWSTATUS_ENABLED)
	}
	if subComp.GetFStatus() == models.FLOWSTATUS_REMOVED {
		return nil, nil
	}
	// gate control
	statusUsage := map[models.FlowDirectionRm]bool{
		models.FLOWDIRECTIONRM_UPLINK:   true,
		models.FLOWDIRECTIONRM_DOWNLINK: true,
	}
	switch subComp.GetFStatus() {
	case models.FLOWSTATUS_ENABLED_UPLINK:
		statusUsage[models.FLOWDIRECTIONRM_DOWNLINK] = false
	case models.FLOWSTATUS_ENABLED_DOWNLINK:
		statusUsage[models.FLOWDIRECTIONRM_UPLINK] = false
	case models.FLOWSTATUS_DISABLED:
		statusUsage[models.FLOWDIRECTIONRM_DOWNLINK] = false
		statusUsage[models.FLOWDIRECTIONRM_UPLINK] = false
	}
	for _, desc := range subComp.GetFDescs() {
		flowDesc, flowDir, err := flowDescFromN5toN7(desc)
		if err != nil {
			return nil, err
		}
		flowInfo := models.NewFlowInformation()
		flowInfo.SetFlowDescription(flowDesc)
		flowInfo.SetFlowDirection(flowDir)
		flowInfo.SetPacketFilterUsage(statusUsage[flowDir])
		flowInfo.SetTosTrafficClass(subComp.GetTosTrCl())
		flows = append(flows, *flowInfo)
	}
	return flows, nil
}

func flowDescFromN5toN7(n5Flow string) (n7Flow string, direction models.FlowDirectionRm, err error) {
	if strings.HasPrefix(n5Flow, "permit out") {
		n7Flow = n5Flow
		direction = models.FLOWDIRECTIONRM_DOWNLINK
	} else if strings.HasPrefix(n5Flow, "permit in") {
		n7Flow = strings.ReplaceAll(n5Flow, "permit in", "permit out")
		direction = models.FLOWDIRECTIONRM_UPLINK
	} else if strings.HasPrefix(n5Flow, "permit inout") {
		n7Flow = strings.ReplaceAll(n5Flow, "permit inout", "permit out")
		direction = models.FLOWDIRECTIONRM_BIDIRECTIONAL
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
	if comp.GetFStatus() == models.FLOWSTATUS_REMOVED {
		updatedQosData.SetMaxbrDl("")
		updatedQosData.SetMaxbrUl("")
		return updatedQosData, ulExist, dlExist
	}
	maxBwUl := 0.0
	maxBwDl := 0.0
	minBwUl := 0.0
	minBwDl := 0.0
	for _, subsComp := range comp.GetMedSubComps() {
		for _, flow := range subsComp.GetFDescs() {
			_, dir, err := flowDescFromN5toN7(flow)
			if err != nil {
				logger.PolicyAuthorizationLog.Errorf(
					"flowDescFromN5toN7 error in updateQosInMedComp: %+v", err)
			}
			both := false
			if dir == models.FLOWDIRECTIONRM_BIDIRECTIONAL {
				both = true
			}
			if subsComp.GetFlowUsage() != models.FLOWUSAGE_RTCP {
				// not RTCP
				if both || dir == models.FLOWDIRECTIONRM_UPLINK {
					ulExist = true
					if comp.GetMarBwUl() != "" {
						bwUl, err := pcfContext.ConvertBitRateToKbps(comp.GetMarBwUl())
						if err != nil {
							logger.PolicyAuthorizationLog.Errorf(
								"pcfContext ConvertBitRateToKbps error in updateQosInMedComp: %+v", err)
						}
						maxBwUl += bwUl
					}
					if comp.GetMirBwUl() != "" {
						bwUl, err := pcfContext.ConvertBitRateToKbps(comp.GetMirBwUl())
						if err != nil {
							logger.PolicyAuthorizationLog.Errorf(
								"pcfContext ConvertBitRateToKbps error in updateQosInMedComp: %+v", err)
						}
						minBwUl += bwUl
					}
				}
				if both || dir == models.FLOWDIRECTIONRM_DOWNLINK {
					dlExist = true
					if comp.GetMarBwDl() != "" {
						bwDl, err := pcfContext.ConvertBitRateToKbps(comp.GetMarBwDl())
						if err != nil {
							logger.PolicyAuthorizationLog.Errorf(
								"pcfContext ConvertBitRateToKbps error in updateQosInMedComp: %+v", err)
						}
						maxBwDl += bwDl
					}
					if comp.GetMirBwDl() != "" {
						bwDl, err := pcfContext.ConvertBitRateToKbps(comp.GetMirBwDl())
						if err != nil {
							logger.PolicyAuthorizationLog.Errorf(
								"pcfContext ConvertBitRateToKbps error in updateQosInMedComp: %+v", err)
						}
						minBwDl += bwDl
					}
				}
			} else {
				if both || dir == models.FLOWDIRECTIONRM_UPLINK {
					ulExist = true
					if subsComp.GetMarBwUl() != "" {
						bwUl, err := pcfContext.ConvertBitRateToKbps(subsComp.GetMarBwUl())
						if err != nil {
							logger.PolicyAuthorizationLog.Errorf(
								"pcfContext ConvertBitRateToKbps error in updateQosInMedComp: %+v", err)
						}
						maxBwUl += bwUl
					} else if comp.GetMarBwUl() != "" {
						bwUl, err := pcfContext.ConvertBitRateToKbps(comp.GetMarBwUl())
						if err != nil {
							logger.PolicyAuthorizationLog.Errorf(
								"pcfContext ConvertBitRateToKbps error in updateQosInMedComp: %+v", err)
						}
						maxBwUl += (0.05 * bwUl)
					}
				}
				if both || dir == models.FLOWDIRECTIONRM_DOWNLINK {
					dlExist = true
					if subsComp.GetMarBwDl() != "" {
						bwDl, err := pcfContext.ConvertBitRateToKbps(subsComp.GetMarBwDl())
						if err != nil {
							logger.PolicyAuthorizationLog.Errorf(
								"pcfContext ConvertBitRateToKbps error in updateQosInMedComp: %+v", err)
						}
						maxBwDl += bwDl
					} else if comp.GetMarBwDl() != "" {
						bwDl, err := pcfContext.ConvertBitRateToKbps(comp.GetMarBwDl())
						if err != nil {
							logger.PolicyAuthorizationLog.Errorf(
								"pcfContext ConvertBitRateToKbps error in updateQosInMedComp: %+v", err)
						}
						maxBwDl += (0.05 * bwDl)
					}
				}
			}
		}
	}
	// update Downlink MBR
	if maxBwDl == 0.0 {
		updatedQosData.SetMaxbrDl(comp.GetMarBwDl())
	} else {
		updatedQosData.SetMaxbrDl(pcfContext.ConvertBitRateToString(maxBwDl))
	}
	// update Uplink MBR
	if maxBwUl == 0.0 {
		updatedQosData.SetMaxbrUl(comp.GetMarBwUl())
	} else {
		updatedQosData.SetMaxbrUl(pcfContext.ConvertBitRateToString(maxBwUl))
	}
	// if gbr == 0 then assign gbr = mbr

	// update Downlink GBR
	if minBwDl != 0.0 {
		updatedQosData.SetGbrDl(pcfContext.ConvertBitRateToString(minBwDl))
	}
	// update Uplink GBR
	if minBwUl != 0.0 {
		updatedQosData.SetGbrUl(pcfContext.ConvertBitRateToString(minBwUl))
	}
	return updatedQosData, ulExist, dlExist
}

func updateQosInMedSubComp(qosData *models.QosData, comp *models.MediaComponent,
	subsComp *models.MediaSubComponent,
) (updatedQosData models.QosData, ulExist, dlExist bool) {
	updatedQosData = *qosData
	if comp.GetFStatus() == models.FLOWSTATUS_REMOVED {
		updatedQosData.SetMaxbrDl("")
		updatedQosData.SetMaxbrUl("")
		return updatedQosData, false, false
	}
	maxBwUl := 0.0
	maxBwDl := 0.0
	minBwUl := 0.0
	minBwDl := 0.0
	for _, flow := range subsComp.FDescs {
		_, dir, err := flowDescFromN5toN7(flow)
		if err != nil {
			logger.PolicyAuthorizationLog.Errorf(
				"flowDescFromN5toN7 error in updateQosInMedSubComp: %+v", err)
		}
		both := false
		if dir == models.FLOWDIRECTIONRM_BIDIRECTIONAL {
			both = true
		}
		if subsComp.GetFlowUsage() != models.FLOWUSAGE_RTCP {
			// not RTCP
			if both || dir == models.FLOWDIRECTIONRM_UPLINK {
				ulExist = true
				if comp.GetMarBwUl() != "" {
					bwUl, err := pcfContext.ConvertBitRateToKbps(comp.GetMarBwUl())
					if err != nil {
						logger.PolicyAuthorizationLog.Errorf(
							"pcfContext ConvertBitRateToKbps error in updateQosInMedSubComp: %+v", err)
					}
					maxBwUl += bwUl
				}
				if comp.GetMirBwUl() != "" {
					bwUl, err := pcfContext.ConvertBitRateToKbps(comp.GetMirBwUl())
					if err != nil {
						logger.PolicyAuthorizationLog.Errorf(
							"pcfContext ConvertBitRateToKbps error in updateQosInMedSubComp: %+v", err)
					}
					minBwUl += bwUl
				}
			}
			if both || dir == models.FLOWDIRECTIONRM_DOWNLINK {
				dlExist = true
				if comp.GetMarBwDl() != "" {
					bwDl, err := pcfContext.ConvertBitRateToKbps(comp.GetMarBwDl())
					if err != nil {
						logger.PolicyAuthorizationLog.Errorf(
							"pcfContext ConvertBitRateToKbps error in updateQosInMedSubComp: %+v", err)
					}
					maxBwDl += bwDl
				}
				if comp.GetMirBwDl() != "" {
					bwDl, err := pcfContext.ConvertBitRateToKbps(comp.GetMirBwDl())
					if err != nil {
						logger.PolicyAuthorizationLog.Errorf(
							"pcfContext ConvertBitRateToKbps error in updateQosInMedSubComp: %+v", err)
					}
					minBwDl += bwDl
				}
			}
		} else {
			if both || dir == models.FLOWDIRECTIONRM_UPLINK {
				ulExist = true
				if subsComp.GetMarBwUl() != "" {
					bwUl, err := pcfContext.ConvertBitRateToKbps(subsComp.GetMarBwUl())
					if err != nil {
						logger.PolicyAuthorizationLog.Errorf(
							"pcfContext ConvertBitRateToKbps error in updateQosInMedSubComp: %+v", err)
					}
					maxBwUl += bwUl
				} else if comp.GetMarBwUl() != "" {
					bwUl, err := pcfContext.ConvertBitRateToKbps(comp.GetMarBwUl())
					if err != nil {
						logger.PolicyAuthorizationLog.Errorf(
							"pcfContext ConvertBitRateToKbps error in updateQosInMedSubComp: %+v", err)
					}
					maxBwUl += (0.05 * bwUl)
				}
			}
			if both || dir == models.FLOWDIRECTIONRM_DOWNLINK {
				dlExist = true
				if subsComp.GetMarBwDl() != "" {
					bwDl, err := pcfContext.ConvertBitRateToKbps(subsComp.GetMarBwDl())
					if err != nil {
						logger.PolicyAuthorizationLog.Errorf(
							"pcfContext ConvertBitRateToKbps error in updateQosInMedSubComp: %+v", err)
					}
					maxBwDl += bwDl
				} else if comp.GetMarBwDl() != "" {
					bwDl, err := pcfContext.ConvertBitRateToKbps(comp.GetMarBwDl())
					if err != nil {
						logger.PolicyAuthorizationLog.Errorf(
							"pcfContext ConvertBitRateToKbps error in updateQosInMedSubComp: %+v", err)
					}
					maxBwDl += (0.05 * bwDl)
				}
			}
		}
	}

	// update Downlink MBR
	if maxBwDl == 0.0 {
		updatedQosData.SetMaxbrDl(comp.GetMarBwDl())
	} else {
		updatedQosData.SetMaxbrDl(pcfContext.ConvertBitRateToString(maxBwDl))
	}
	// update Uplink MBR
	if maxBwUl == 0.0 {
		updatedQosData.SetMaxbrUl(comp.GetMarBwUl())
	} else {
		updatedQosData.SetMaxbrUl(pcfContext.ConvertBitRateToString(maxBwUl))
	}
	// if gbr == 0 then assign gbr = mbr
	// update Downlink GBR
	if minBwDl != 0.0 {
		updatedQosData.SetGbrDl(pcfContext.ConvertBitRateToString(minBwDl))
	}
	// update Uplink GBR
	if minBwUl != 0.0 {
		updatedQosData.SetGbrUl(pcfContext.ConvertBitRateToString(minBwUl))
	}
	return updatedQosData, ulExist, dlExist
}

func removeMediaComp(appSession *pcfContext.AppSessionData, compN string) {
	idMaps := appSession.RelatedPccRuleIds
	smPolicy := appSession.SmPolicyData
	if idMaps != nil {
		if appSession.AppSessionContext.AscReqData.Get().MedComponents == nil {
			return
		}
		medComponents := *appSession.AppSessionContext.AscReqData.Get().MedComponents
		comp, exist := medComponents[compN]
		if !exist {
			return
		}
		if comp.MedSubComps != nil {
			medSubComps := *comp.MedSubComps
			for fNum := range medSubComps {
				key := fmt.Sprintf("%s-%s", compN, fNum)
				pccRuleID := idMaps[key]
				err := smPolicy.RemovePccRule(pccRuleID, nil)
				if err != nil {
					logger.PolicyAuthorizationLog.Warnln(err.Error())
				}
				delete(appSession.RelatedPccRuleIds, key)
				delete(appSession.PccRuleIdMapToCompId, pccRuleID)
			}
		} else {
			pccRuleID := idMaps[compN]
			err := smPolicy.RemovePccRule(pccRuleID, nil)
			if err != nil {
				logger.PolicyAuthorizationLog.Warnln(err.Error())
			}
			delete(appSession.RelatedPccRuleIds, compN)
			delete(appSession.PccRuleIdMapToCompId, pccRuleID)
		}
		delMedComponents := *appSession.AppSessionContext.AscReqData.Get().MedComponents
		delete(delMedComponents, compN)
	}
}

// func removeMediaSubComp(appSession *pcfContext.AppSessionData, compN, fNum string) {
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
	usageThreshold := models.NewUsageThreshold()
	usageThreshold.SetDuration(*threshrm.Duration.Get())
	usageThreshold.SetTotalVolume(*threshrm.TotalVolume.Get())
	usageThreshold.SetDownlinkVolume(*threshrm.DownlinkVolume.Get())
	usageThreshold.SetUplinkVolume(*threshrm.UplinkVolume.Get())
	return usageThreshold
}

func extractUmData(umID string, eventSubs map[models.AfEventPcf]models.AfNotifMethod,
	threshold *models.UsageThreshold,
) (umData *models.UsageMonitoringData, err error) {
	if _, umExist := eventSubs[models.AFEVENTPCF_USAGE_REPORT]; umExist {
		if threshold == nil {
			return nil, fmt.Errorf("UsageThreshold is nil in USAGE REPORT Subscription")
		} else {
			tmp := util.CreateUmData(umID, *threshold)
			umData = &tmp
		}
	}
	return
}

func modifyRemainBitRate(smPolicy *pcfContext.UeSmPolicyData, qosData *models.QosData,
	ulExist, dlExist bool,
) *models.ProblemDetails {
	// if request GBR == 0, qos GBR = MBR
	// if request GBR > remain GBR, qos GBR = remain GBR
	if ulExist {
		if qosData.GetGbrUl() == "" {
			// err = pcfContext.DecreaseRamainBitRate(smPolicy.RemainGbrUL, qosData.MaxbrUl)
			if err := pcfContext.DecreaseRamainBitRate(smPolicy.RemainGbrUL, qosData.GetMaxbrUl()); err != nil {
				qosData.SetGbrUl(pcfContext.DecreaseRamainBitRateToZero(smPolicy.RemainGbrUL))
			} else {
				qosData.SetGbrUl(qosData.GetMaxbrUl())
			}
		} else {
			// err = pcfContext.DecreaseRamainBitRate(smPolicy.RemainGbrUL, qosData.GbrUl)
			if err := pcfContext.DecreaseRamainBitRate(smPolicy.RemainGbrUL, qosData.GetGbrUl()); err != nil {
				problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
				// sendProblemDetail(httpChannel, err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
				return problemDetail
			}
		}
	}
	if dlExist {
		if qosData.GetGbrDl() == "" {
			// err = pcfContext.DecreaseRamainBitRate(smPolicy.RemainGbrDL, qosData.MaxbrDl)
			if err := pcfContext.DecreaseRamainBitRate(smPolicy.RemainGbrDL, qosData.GetMaxbrDl()); err != nil {
				qosData.SetGbrDl(pcfContext.DecreaseRamainBitRateToZero(smPolicy.RemainGbrDL))
			} else {
				qosData.SetGbrDl(qosData.GetMaxbrDl())
			}
		} else {
			// err = pcfContext.DecreaseRamainBitRate(smPolicy.RemainGbrDL, qosData.GbrDl)
			if err := pcfContext.DecreaseRamainBitRate(smPolicy.RemainGbrDL, qosData.GetGbrDl()); err != nil {
				// if Policy failed, revert remain GBR to original GBR
				pcfContext.IncreaseRamainBitRate(smPolicy.RemainGbrUL, *qosData.GbrUl.Get())
				problemDetail := util.GetProblemDetail(err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
				// sendProblemDetail(httpChannel, err.Error(), util.REQUESTED_SERVICE_NOT_AUTHORIZED)
				return problemDetail
			}
		}
	}
	return nil
}

func provisioningOfTrafficRoutingInfo(smPolicy *pcfContext.UeSmPolicyData, appID string,
	routeReq *models.AfRoutingRequirement, fStatus models.FlowStatus,
) *models.PccRule {
	var tcData *models.TrafficControlData
	var pccRule *models.PccRule

	// TODO : handle temporal or spatial validity
	_, existingPccRule, found := util.GetPccRuleByAfAppId(smPolicy.PolicyDecision.PccRules, appID)
	if found {
		pccRule = &existingPccRule
		// Update TcData
		var tcID string
		if len(pccRule.GetRefTcData()) > 0 {
			// 1 PCC rule only supports 1 TrafficControlData
			// TODO: 1 PCC rule supports multiple TrafficControlData
			// Re-use the original tcID
			tcID = pccRule.GetRefTcData()[0]
			if !smPolicy.PolicyDecision.HasTraffContDecs() {
				logger.PolicyAuthorizationLog.Errorf("TraffContDecs is nil, tcID[%s]", tcID)
				tcData = util.CreateTcData(0, tcID, fStatus)
			} else {
				if data, exists := (*smPolicy.PolicyDecision.TraffContDecs)[tcID]; exists {
					tcData = &data
				} else {
					logger.PolicyAuthorizationLog.Errorf("TraffContDecs[%s] not found", tcID)
					tcData = util.CreateTcData(0, tcID, fStatus)
				}
			}
		} else {
			// tcID's number equals to pccRuleID's number
			tcID = strings.ReplaceAll(pccRule.GetPccRuleId(), "PccRule", "Tc")
			tcData = util.CreateTcData(0, tcID, fStatus)
			pccRule.SetRefTcData([]string{tcID})
		}
		tcData.SetRouteToLocs(routeReq.GetRouteToLocs())
		if routeReq.HasUpPathChgSub() {
			tcData.SetUpPathChgEvent(routeReq.GetUpPathChgSub())
		} else {
			tcData.UnsetUpPathChgEvent()
		}
		if routeReq.HasAppReloc() {
			pccRule.SetAppReloc(routeReq.GetAppReloc())
		} else {
			pccRule.AppReloc = nil
		}
		util.SetPccRuleRelatedData(smPolicy.PolicyDecision, pccRule, tcData, nil, nil, nil)
		logger.PolicyAuthorizationLog.Infof("update Traffic Control Data[%s] in PCC rule[%s]",
			tcID, pccRule.GetPccRuleId())
	} else {
		// Create a Pcc Rule if afappID dose not match any pcc rule
		maxPrecedence := getMaxPrecedence(smPolicy.PolicyDecision.GetPccRules())
		pccRule = util.CreatePccRule(smPolicy.PccRuleIdGenarator, maxPrecedence+1, nil, appID)
		tcData = util.CreateTcData(smPolicy.PccRuleIdGenarator, "", fStatus)
		tcData.SetRouteToLocs(routeReq.GetRouteToLocs())
		if routeReq.HasUpPathChgSub() {
			tcData.SetUpPathChgEvent(routeReq.GetUpPathChgSub())
		} else {
			tcData.UnsetUpPathChgEvent()
		}
		pccRule.SetRefTcData([]string{tcData.GetTcId()})
		util.SetPccRuleRelatedData(smPolicy.PolicyDecision, pccRule, tcData, nil, nil, nil)
		smPolicy.PccRuleIdGenarator++
		logger.PolicyAuthorizationLog.Infof("create PCC rule[%s] with new Traffic Control Data[%s]",
			pccRule.GetPccRuleId(), tcData.GetTcId())
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
