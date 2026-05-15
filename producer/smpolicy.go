// SPDX-FileCopyrightText: 2025 Canonical Ltd
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package producer

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/mohae/deepcopy"
	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/logger"
	stats "github.com/omec-project/pcf/metrics"
	"github.com/omec-project/pcf/polling"
	"github.com/omec-project/pcf/util"
	"github.com/omec-project/util/httpwrapper"
	"github.com/omec-project/util/idgenerator"
)

var getSlicePccPolicy = polling.GetSlicePccPolicy

// SmPoliciesPost -
func HandleCreateSmPolicyRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SMpolicylog.Infoln("handle CreateSmPolicy")
	requestDataType := request.Body.(models.SmPolicyContextData)
	header, response, problemDetails := createSMPolicyProcedure(requestDataType)
	if response != nil {
		stats.IncrementPcfSmPolicyStats("create", requestDataType.Dnn, "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusCreated, header, response)
	} else if problemDetails != nil {
		stats.IncrementPcfSmPolicyStats("create", requestDataType.Dnn, "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	} else {
		stats.IncrementPcfSmPolicyStats("create", requestDataType.Dnn, "FAILURE")
		return httpwrapper.NewResponse(http.StatusNotFound, nil, nil)
	}
}

func createSMPolicyProcedure(request models.SmPolicyContextData) (
	header http.Header, response *models.SmPolicyDecision, problemDetails *models.ProblemDetails,
) {
	var err error
	logger.SMpolicylog.Debugln("handle Create SM Policy Request")

	reqNnssai := request.GetSliceInfo()
	if request.GetSupi() == "" || reqNnssai.GetSst() < 0 || reqNnssai.GetSst() > math.MaxUint8 {
		problemDetail := util.GetProblemDetail("Errorneous/Missing Mandotory IE", util.ERROR_INITIAL_PARAMETERS)
		logger.SMpolicylog.Warnln("Errorneous/Missing Mandotory IE", util.ERROR_INITIAL_PARAMETERS)
		return nil, nil, problemDetail
	}

	pcfSelf := pcfContext.PCF_Self()
	var ue *pcfContext.UeContext
	if val, exist := pcfSelf.UePool.Load(request.Supi); exist {
		ue = val.(*pcfContext.UeContext)
	}

	if ue == nil {
		problemDetail := util.GetProblemDetail("Supi is not supported in PCF", util.USER_UNKNOWN)
		logger.SMpolicylog.Warnf("Supi[%s] is not supported in PCF", request.Supi)
		return nil, nil, problemDetail
	}
	udrUri := getUdrUri(ue)
	if udrUri == "" {
		problemDetail := util.GetProblemDetail("Can't find corresponding UDR with UE", util.USER_UNKNOWN)
		logger.SMpolicylog.Warnf("can not find corresponding UDR with UE[%s]", ue.Supi)
		return nil, nil, problemDetail
	}
	var smData *models.SmPolicyData
	smPolicyID := fmt.Sprintf("%s-%d", ue.Supi, request.PduSessionId)
	smPolicyData := ue.SmPolicyData[smPolicyID]
	if smPolicyData == nil || smPolicyData.SmPolicyData == nil {
		client := util.GetNudrClient(udrUri)
		var response *http.Response
		apiReadSessionManagementPolicyDataRequest := client.SessionManagementPolicyDataDocumentAPI.ReadSessionManagementPolicyData(context.Background(), ue.Supi)
		apiReadSessionManagementPolicyDataRequest = apiReadSessionManagementPolicyDataRequest.Snssai(request.SliceInfo)
		apiReadSessionManagementPolicyDataRequest = apiReadSessionManagementPolicyDataRequest.Dnn(request.Dnn)
		smData, response, err = client.SessionManagementPolicyDataDocumentAPI.ReadSessionManagementPolicyDataExecute(apiReadSessionManagementPolicyDataRequest)
		if err != nil || response == nil || response.StatusCode != http.StatusOK {
			problemDetail := util.GetProblemDetail("Can't find UE SM Policy Data in UDR", util.USER_UNKNOWN)
			logger.SMpolicylog.Warnf("can not find UE[%s] SM Policy Data in UDR", ue.Supi)
			return nil, nil, problemDetail
		}
		defer func() {
			if rspCloseErr := response.Body.Close(); rspCloseErr != nil {
				logger.SMpolicylog.Errorf(
					"ReadSessionManagementPolicyDataExecute response body cannot close: %+v", rspCloseErr)
			}
		}()
		// TODO: subscribe to UDR
	} else {
		smData = smPolicyData.SmPolicyData
	}
	amPolicy := ue.FindAMPolicy(request.GetAccessType(), request.ServingNetwork)
	if amPolicy == nil {
		problemDetail := util.GetProblemDetail("Can't find corresponding AM Policy", util.POLICY_CONTEXT_DENIED)
		logger.SMpolicylog.Warnln("can not find corresponding AM Policy")
		// message.SendHttpResponseMessage(httpChannel, nil, int(rsp.Status), rsp)
		return nil, nil, problemDetail
	}
	// TODO: check service restrict
	if ue.Gpsi == "" {
		ue.Gpsi = request.GetGpsi()
	}
	if ue.Pei == "" {
		ue.Pei = request.GetPei()
	}
	if smPolicyData != nil {
		delete(ue.SmPolicyData, smPolicyID)
	}
	smPolicyData = ue.NewUeSmPolicyData(smPolicyID, request, smData)

	// Policy Decision
	snssai := models.Snssai{
		Sst: request.SliceInfo.GetSst(),
		Sd:  request.SliceInfo.Sd,
	}
	decision, problemDetail := buildSmPolicyDecision(ue.Supi, snssai, request.Dnn, request.SubsSessAmbr, request.SubsDefQos)
	if problemDetail != nil {
		return nil, nil, problemDetail
	}
	/*var ambr *models.Ambr
	//sstStr := strconv.Itoa(int(request.SliceInfo.Sst))
	if cAmbr, ok := pcfSelf.AmbrMap[sstStr+request.SliceInfo.Sd]; !ok {
		ambr = request.SubsSessAmbr
	} else {
		ambr = &cAmbr
	}*/
	/*	SessRuleId := fmt.Sprintf("SessRuleId-%d", request.PduSessionId)
		sessRule := models.SessionRule{
			AuthSessAmbr: ambr,
			SessRuleId:   SessRuleId,
			// RefUmData
			// RefCondData
		}

		//Check if local config has pre-configured def Qos for the slice(via ROC)
		var defQos *models.SubscribedDefaultQos
		if dQos, ok := pcfSelf.DefQosMap[sstStr+request.SliceInfo.Sd]; !ok {
			defQos = request.SubsDefQos
		} else {
			//ARP and Priority not coming from ROC yet, copy from request
			dQos.Arp = request.SubsDefQos.Arp
			dQos.PriorityLevel = request.SubsDefQos.PriorityLevel
			defQos = &dQos
		}

		if defQos != nil {
			sessRule.AuthDefQos = &models.AuthorizedDefaultQos{
				Var5qi:        defQos.Var5qi,
				Arp:           defQos.Arp,
				PriorityLevel: defQos.PriorityLevel,
				// AverWindow
				// MaxDataBurstVol
			}
		}
		decision.SessRules[SessRuleId] = &sessRule
	*/
	// TODO: See how UDR used
	dnnData := util.GetSMPolicyDnnData(*smData, request.SliceInfo, request.Dnn)
	if dnnData != nil {
		decision.Online = dnnData.Online
		decision.Offline = dnnData.Offline
		decision.Ipv4Index = dnnData.Ipv4Index
		decision.Ipv6Index = dnnData.Ipv6Index
		// Set Aggregate GBR if exist
		if dnnData.GetGbrDl() != "" {
			var gbrDL float64
			gbrDL, err = pcfContext.ConvertBitRateToKbps(dnnData.GetGbrDl())
			if err != nil {
				logger.SMpolicylog.Warnln(err.Error())
			} else {
				smPolicyData.RemainGbrDL = &gbrDL
				logger.SMpolicylog.Debugf("SM Policy Dnn[%s] Data Aggregate DL GBR[%.2f Kbps]", request.Dnn, gbrDL)
			}
		}
		if dnnData.GetGbrUl() != "" {
			var gbrUL float64
			gbrUL, err = pcfContext.ConvertBitRateToKbps(dnnData.GetGbrUl())
			if err != nil {
				logger.SMpolicylog.Warnln(err.Error())
			} else {
				smPolicyData.RemainGbrUL = &gbrUL
				logger.SMpolicylog.Debugf("SM Policy Dnn[%s] Data Aggregate UL GBR[%.2f Kbps]", request.Dnn, gbrUL)
			}
		}
	} else {
		logger.SMpolicylog.Warnf(
			"Policy Subscription Info: SMPolicyDnnData is null for dnn[%s] in UE[%s]", request.Dnn, ue.Supi)
		decision.Online = request.Online
		decision.Offline = request.Offline
	}

	requestSuppFeat, err := pcfContext.NewSupportedFeature(request.GetSuppFeat())
	if err != nil {
		logger.SMpolicylog.Errorf("NewSupportedFeature error: %+v", err)
	}
	suppFeat := pcfSelf.PcfSuppFeats[models.SERVICENAME_NPCF_SMPOLICYCONTROL]
	result, err := suppFeat.NegotiateWith(requestSuppFeat)
	if err != nil {
		logger.SMpolicylog.Errorf("NegotiateWith error: %+v", err)
	}
	decision.SuppFeat = openapi.PtrString(result.String())
	decision.QosFlowUsage = request.QosFlowUsage
	// TODO: Trigger about UMC, ADC, NetLoc,...
	decision.PolicyCtrlReqTriggers = util.PolicyControlReqTrigToArray(0x40780f)

	smPolicyData.PolicyDecision = decision
	// TODO: PCC rule, PraInfo ...
	locationHeader := util.GetResourceUri(models.SERVICENAME_NPCF_SMPOLICYCONTROL, smPolicyID)
	header = http.Header{
		"Location": {locationHeader},
	}
	logger.SMpolicylog.Debugf("SMPolicy PduSessionId[%d] Create", request.PduSessionId)
	logger.SMpolicylog.Infof("SM Policy Decision Sent to SMF: %v", decision)

	return header, decision, nil
}

func buildSmPolicyDecision(imsi string, snssai models.Snssai, dnn string, subscribedSessionAmbr *models.Ambr, subscribedQos *models.SubscribedDefaultQos) (response *models.SmPolicyDecision, problemDetails *models.ProblemDetails) {
	pccPolicy := getSlicePccPolicy(snssai)
	if pccPolicy == nil {
		problemDetail := util.GetProblemDetail("Can't find in local policy", util.USER_UNKNOWN)
		logger.SMpolicylog.Warnf("can not find slice %+v in local policy", snssai)
		return nil, problemDetail
	}
	logger.SMpolicylog.Debugf("pcc Policy data exists in PcfPccPolicyData for slice %+v", snssai)

	decision := initSmPolicyDecisionFromPccPolicy(pccPolicy)
	sessionRules, err := polling.GetImsiSessionRules(dnn, imsi)
	if err != nil {
		logger.SMpolicylog.Warnf("failed to get the session rules from the webconsole, using default values for %s, %v", imsi, err)
		decision.SessRules = buildDefaultSessionPolicy(dnn, subscribedSessionAmbr, subscribedQos)
		return &decision, nil
	}

	if len(sessionRules) == 0 {
		logger.SMpolicylog.Warnf("no session rules found for %s in DNN %s", imsi, dnn)
		problemDetail := util.GetProblemDetail("can not find local policy", util.USER_UNKNOWN)
		return nil, problemDetail
	}
	for _, sessRule := range sessionRules {
		var copiedRule models.SessionRule
		err := util.DeepCopyViaJSON(*sessRule, &copiedRule)
		if err != nil {
			logger.SMpolicylog.Errorf("failed to copy session rule %s: %v", sessRule.SessRuleId, err)
			continue
		}
		(*decision.SessRules)[sessRule.SessRuleId] = copiedRule
	}
	return &decision, nil
}

func initSmPolicyDecisionFromPccPolicy(pccPolicy *polling.PccPolicy) models.SmPolicyDecision {
	sessRules := make(map[string]models.SessionRule)
	pccRules := make(map[string]models.PccRule)
	qosDecs := make(map[string]models.QosData)
	traffContDecs := make(map[string]models.TrafficControlData)
	decision := models.NewSmPolicyDecision()
	for id, rule := range pccPolicy.PccRules {
		pccRules[id] = deepcopy.Copy(*rule).(models.PccRule)
	}
	for id, qos := range pccPolicy.QosDecs {
		qosDecs[id] = deepcopy.Copy(*qos).(models.QosData)
	}
	for id, tc := range pccPolicy.TraffContDecs {
		traffContDecs[id] = deepcopy.Copy(*tc).(models.TrafficControlData)
	}
	decision.SetSessRules(sessRules) // This is just to initialize the map/pointer
	decision.SetPccRules(pccRules)
	decision.SetQosDecs(qosDecs)
	decision.SetTraffContDecs(traffContDecs)
	return *decision
}

func buildDefaultSessionPolicy(dnn string, ambr *models.Ambr, qos *models.SubscribedDefaultQos) *map[string]models.SessionRule {
	idGenerator := idgenerator.NewGenerator(1, math.MaxInt16)
	id, err := idGenerator.Allocate()
	if err != nil {
		logger.CtxLog.Errorf("ID generator allocation failed: %v", err)
		return nil
	}
	key := fmt.Sprintf("%s-%d", dnn, id)
	buildSessPolicy := map[string]models.SessionRule{
		key: *buildDefaultSessionRule(key, ambr, qos),
	}
	return &buildSessPolicy
}

func buildDefaultSessionRule(key string, ambr *models.Ambr, qos *models.SubscribedDefaultQos) *models.SessionRule {
	authDefQos := models.NewAuthorizedDefaultQos()
	sessionRule := models.NewSessionRule(key)
	if ambr != nil && qos != nil {
		authDefQos.SetVar5qi(qos.GetVar5qi())
		authDefQos.SetArp(qos.GetArp())
		sessionRule.SetAuthDefQos(*authDefQos)
		sessionRule.SetAuthSessAmbr(*ambr)
	} else {
		authDefQos.SetVar5qi(5)
		authDefQos.SetArp(models.Arp{PriorityLevel: *openapi.NewNullableInt32(openapi.PtrInt32(1))})
		sessionRule.SetAuthDefQos(*authDefQos)
		sessionRule.SetAuthSessAmbr(models.Ambr{
			Downlink: "1 Mbps",
			Uplink:   "1 Mbps",
		})
	}
	return sessionRule
}

// SmPoliciessmPolicyIDDeletePost -
func HandleDeleteSmPolicyContextRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SMpolicylog.Infoln("handle DeleteSmPolicyContext")
	smPolicyID := request.Params["smPolicyId"]
	getResponse, getProblemDetails := getSmPolicyContextProcedure(smPolicyID)
	smPolicyDnn := "UNKNOWN_DNN"
	if getProblemDetails == nil {
		smPolicyDnn = getResponse.Context.Dnn
	}
	problemDetails := deleteSmPolicyContextProcedure(smPolicyID)
	if problemDetails != nil {
		stats.IncrementPcfSmPolicyStats("delete", smPolicyDnn, "FAILURE")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	} else {
		stats.IncrementPcfSmPolicyStats("delete", smPolicyDnn, "SUCCESS")
		return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
	}
}

func deleteSmPolicyContextProcedure(smPolicyID string) *models.ProblemDetails {
	logger.AMpolicylog.Debugln("handle SM Policy Delete")

	pcfSelf := pcfContext.PCF_Self()
	ue := pcfSelf.PCFUeFindByPolicyId(smPolicyID)
	logger.SMpolicylog.Infof("smPolicyID: %v, ue: %v", smPolicyID, ue)
	if ue == nil || ue.SmPolicyData[smPolicyID] == nil {
		problemDetail := util.GetProblemDetail("smPolicyID not found in PCF", util.CONTEXT_NOT_FOUND)
		logger.SMpolicylog.Warnln(problemDetail.Detail)
		return problemDetail
	}

	smPolicy := ue.SmPolicyData[smPolicyID]

	// Unsubscrice UDR
	delete(ue.SmPolicyData, smPolicyID)
	logger.SMpolicylog.Debugf("SMPolicy smPolicyID[%s] DELETE", smPolicyID)

	// Release related App Session
	terminationInfo := models.TerminationInfo{
		TermCause: models.TERMINATIONCAUSE_PDU_SESSION_TERMINATION,
	}
	for appSessionID := range smPolicy.AppSessions {
		if val, exist := pcfSelf.AppSessionPool.Load(appSessionID); exist {
			appSession := val.(*pcfContext.AppSessionData)
			SendAppSessionTermination(appSession, terminationInfo)
			pcfSelf.AppSessionPool.Delete(appSessionID)
			logger.SMpolicylog.Debugf("SMPolicy[%s] DELETE Related AppSession[%s]", smPolicyID, appSessionID)
		}
	}
	return nil
}

// SmPoliciessmPolicyIDGet -
func HandleGetSmPolicyContextRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SMpolicylog.Infoln("handle GetSmPolicyContext")
	smPolicyID := request.Params["smPolicyID"]
	response, problemDetails := getSmPolicyContextProcedure(smPolicyID)
	if response != nil {
		stats.IncrementPcfSmPolicyStats("get", response.Context.Dnn, "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		stats.IncrementPcfSmPolicyStats("get", "UNKNOWN_DNN", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	stats.IncrementPcfSmPolicyStats("get", "UNKNOWN_DNN", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getSmPolicyContextProcedure(smPolicyID string) (
	response *models.SmPolicyControl, problemDetails *models.ProblemDetails,
) {
	logger.SMpolicylog.Debugln("handle GET SM Policy Request")

	ue := pcfContext.PCF_Self().PCFUeFindByPolicyId(smPolicyID)
	if ue == nil || ue.SmPolicyData[smPolicyID] == nil {
		problemDetail := util.GetProblemDetail("smPolicyID not found in PCF", util.CONTEXT_NOT_FOUND)
		logger.SMpolicylog.Warnln(problemDetail.Detail)
		return nil, problemDetail
	}
	smPolicyData := ue.SmPolicyData[smPolicyID]
	response = models.NewSmPolicyControl(*smPolicyData.PolicyContext, *smPolicyData.PolicyDecision)
	logger.SMpolicylog.Debugf("SMPolicy smPolicyID[%s] GET", smPolicyID)
	return response, nil
}

// SmPoliciessmPolicyIDUpdatePost -
func HandleUpdateSmPolicyContextRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SMpolicylog.Infoln("handle UpdateSmPolicyContext")
	requestDataType := request.Body.(models.SmPolicyUpdateContextData)
	smPolicyID := request.Params["smPolicyId"]
	getResponse, getProblemDetails := getSmPolicyContextProcedure(smPolicyID)
	smPolicyDnn := "UNKNOWN_DNN"
	if getProblemDetails == nil {
		smPolicyDnn = getResponse.Context.Dnn
	}
	response, problemDetails := updateSmPolicyContextProcedure(requestDataType, smPolicyID)
	if response != nil {
		stats.IncrementPcfSmPolicyStats("update", smPolicyDnn, "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		stats.IncrementPcfSmPolicyStats("update", smPolicyDnn, "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	stats.IncrementPcfSmPolicyStats("update", smPolicyDnn, "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func updateSmPolicyContextProcedure(request models.SmPolicyUpdateContextData, smPolicyID string) (
	response *models.SmPolicyDecision, problemDetails *models.ProblemDetails,
) {
	logger.SMpolicylog.Debugln("handle updateSmPolicyContext")

	ue := pcfContext.PCF_Self().PCFUeFindByPolicyId(smPolicyID)
	if ue == nil || ue.SmPolicyData[smPolicyID] == nil {
		problemDetail := util.GetProblemDetail("smPolicyID not found in PCF", util.CONTEXT_NOT_FOUND)
		logger.SMpolicylog.Warnln(problemDetail.Detail)
		return nil, problemDetail
	}
	smPolicy := ue.SmPolicyData[smPolicyID]
	smPolicyDecision := smPolicy.PolicyDecision
	smPolicyContext := smPolicy.PolicyContext
	errCause := ""

	// For App Session Notification
	afEventsNotification := models.EventsNotification{}
	for _, trigger := range request.RepPolicyCtrlReqTriggers {
		switch trigger {
		case models.POLICYCONTROLREQUESTTRIGGER_PLMN_CH: // PLMN Change
			if request.ServingNetwork == nil {
				errCause = "Serving Network is nil in Trigger PLMN_CH"
				break
			}
			smPolicyContext.ServingNetwork = request.ServingNetwork
			afEventsNotification.PlmnId = models.NewPlmnIdNid(request.ServingNetwork.GetMcc(), request.ServingNetwork.GetMnc())
			afNotif := models.AfEventNotification{
				Event: models.AFEVENTPCF_PLMN_CHG,
			}
			afEventsNotification.EvNotifs = append(afEventsNotification.EvNotifs, afNotif)

			logger.SMpolicylog.Debugf("SM Policy Update(%s) Successfully", trigger)
		case models.POLICYCONTROLREQUESTTRIGGER_RES_MO_RE:
			// UE intiate resource modification to SMF (subsclause 4.2.4.17 in TS29512)
			req := request.UeInitResReq
			if req == nil {
				errCause = "UeInitResReq is nil in Trigger RES_MO_RE"
				break
			}
			switch req.RuleOp {
			case models.RULEOPERATION_CREATE_PCC_RULE:
				if req.ReqQos == nil || len(req.PackFiltInfo) < 1 {
					errCause = "Parameter Erroneous/Missing in Create Pcc Rule"
					break
				}
				// TODO: Packet Filters are covered by outstanding pcc rule
				id := smPolicy.PccRuleIdGenarator
				infos := util.ConvertPacketInfoToFlowInformation(req.PackFiltInfo)
				if infos == nil {
					errCause = "Failed to convert packet filter info"
					break
				}
				// Set PackFiltId
				for i := range infos {
					infos[i].PackFiltId = openapi.PtrString(util.GetPackFiltId(smPolicy.PackFiltIdGenarator))
					smPolicy.PackFiltIdGenarator++
				}
				pccRule := util.CreatePccRule(id, req.GetPrecedence(), infos, "")
				// Add Traffic control Data
				tcData := util.CreateTcData(id, "", "")
				// TODO: ARP use real Data
				qosData := util.CreateQosData(id, req.ReqQos.Var5qi, 15)
				// TODO: Set MBR
				gbrDl, gbrUl, err := smPolicy.DecreaseRemainGBR(req.ReqQos)
				if err != nil {
					problemDetail := util.GetProblemDetail(err.Error(), util.ERROR_TRAFFIC_MAPPING_INFO_REJECTED)
					logger.SMpolicylog.Warnln(problemDetail.Detail)
					return nil, problemDetail
				}
				qosData.GbrDl = *openapi.NewNullableString(openapi.PtrString(gbrDl))
				qosData.GbrUl = *openapi.NewNullableString(openapi.PtrString(gbrUl))
				if qosData.GetGbrDl() != "" {
					logger.SMpolicylog.Debugf("SM Policy Dnn[%s] Data Aggregate decrease %s and then DL GBR remain[%.2f Kbps]",
						smPolicyContext.Dnn, qosData.GbrDl, *smPolicy.RemainGbrDL)
				}
				if qosData.GetGbrUl() != "" {
					logger.SMpolicylog.Debugf("SM Policy Dnn[%s] Data Aggregate decrease %s and then UL GBR remain[%.2f Kbps]",
						smPolicyContext.Dnn, qosData.GbrUl, *smPolicy.RemainGbrUL)
				}
				util.SetPccRuleRelatedData(smPolicyDecision, pccRule, tcData, &qosData, nil, nil)
				// link Packet filters to PccRule
				for _, info := range infos {
					smPolicy.PackFiltMapToPccRuleId[info.GetPackFiltId()] = pccRule.PccRuleId
				}
				smPolicy.PccRuleIdGenarator++
			case models.RULEOPERATION_DELETE_PCC_RULE:
				if req.GetPccRuleId() == "" {
					errCause = "Parameter Erroneous/Missing in Create Pcc Rule"
					break
				}
				err := smPolicy.RemovePccRule(req.GetPccRuleId(), nil)
				if err != nil {
					errCause = err.Error()
				}
			case models.RULEOPERATION_MODIFY_PCC_RULE_AND_ADD_PACKET_FILTERS,
				models.RULEOPERATION_MODIFY_PCC_RULE_AND_REPLACE_PACKET_FILTERS,
				models.RULEOPERATION_MODIFY_PCC_RULE_AND_DELETE_PACKET_FILTERS,
				models.RULEOPERATION_MODIFY_PCC_RULE_WITHOUT_MODIFY_PACKET_FILTERS:
				if req.GetPccRuleId() == "" ||
					(req.RuleOp != models.RULEOPERATION_MODIFY_PCC_RULE_WITHOUT_MODIFY_PACKET_FILTERS &&
						len(req.PackFiltInfo) < 1) {
					errCause = "Parameter Erroneous/Missing in Modify Pcc Rule"
					break
				}
				if rule, exist := smPolicyDecision.PccRules[req.GetPccRuleId()]; exist {
					// Modify Qos if included
					rule.Precedence = req.Precedence
					if req.ReqQos != nil && len(rule.RefQosData) != 0 {
						qosId := rule.RefQosData[0]
						if qosData, exist := smPolicyDecision.GetQosDecs()[qosId]; exist {
							origUl, origDl := smPolicy.IncreaseRemainGBR(qosId)
							gbrDl, gbrUl, err := smPolicy.DecreaseRemainGBR(req.ReqQos)
							if err != nil {
								smPolicy.RemainGbrDL = origDl
								smPolicy.RemainGbrUL = origUl
								problemDetail := util.GetProblemDetail(err.Error(), util.ERROR_TRAFFIC_MAPPING_INFO_REJECTED)
								logger.SMpolicylog.Warnln(problemDetail.Detail)
								return nil, problemDetail
							}
							qosData.Var5qi = openapi.PtrInt32(req.ReqQos.GetVar5qi())
							qosData.GbrDl = *openapi.NewNullableString(openapi.PtrString(gbrDl))
							qosData.GbrUl = *openapi.NewNullableString(openapi.PtrString(gbrUl))
							if qosData.GetGbrDl() != "" {
								logger.SMpolicylog.Debugf("SM Policy Dnn[%s] Data Aggregate decrease %s and then DL GBR remain[%.2f Kbps]",
									smPolicyContext.Dnn, qosData.GbrDl, *smPolicy.RemainGbrDL)
							}
							if qosData.GetGbrUl() != "" {
								logger.SMpolicylog.Debugf("SM Policy Dnn[%s] Data Aggregate decrease %s and then UL GBR remain[%.2f Kbps]",
									smPolicyContext.Dnn, qosData.GbrUl, *smPolicy.RemainGbrUL)
							}
							(*smPolicyDecision.QosDecs)[qosId] = qosData
						} else {
							errCause = "Parameter Erroneous/Missing in Modify Pcc Rule"
							break
						}
					}
					infos := util.ConvertPacketInfoToFlowInformation(req.PackFiltInfo)
					if infos == nil {
						errCause = "Failed to convert packet filter info"
						break
					}
					switch req.RuleOp {
					case models.RULEOPERATION_MODIFY_PCC_RULE_AND_ADD_PACKET_FILTERS:
						// Set PackFiltId
						for i := range infos {
							infos[i].PackFiltId = openapi.PtrString(util.GetPackFiltId(smPolicy.PackFiltIdGenarator))
							smPolicy.PackFiltMapToPccRuleId[infos[i].GetPackFiltId()] = req.GetPccRuleId()
							smPolicy.PackFiltIdGenarator++
						}
						rule.FlowInfos = append(rule.FlowInfos, infos...)
					case models.RULEOPERATION_MODIFY_PCC_RULE_AND_REPLACE_PACKET_FILTERS:
						// Replace all Packet Filters
						for _, info := range rule.FlowInfos {
							delete(smPolicy.PackFiltMapToPccRuleId, info.GetPackFiltId())
						}
						// Set PackFiltId
						for i := range infos {
							infos[i].PackFiltId = openapi.PtrString(util.GetPackFiltId(smPolicy.PackFiltIdGenarator))
							smPolicy.PackFiltMapToPccRuleId[infos[i].GetPackFiltId()] = req.GetPccRuleId()
							smPolicy.PackFiltIdGenarator++
						}
						rule.FlowInfos = infos
					case models.RULEOPERATION_MODIFY_PCC_RULE_AND_DELETE_PACKET_FILTERS:
						removeId := make(map[string]bool)
						for _, info := range infos {
							delete(smPolicy.PackFiltMapToPccRuleId, info.GetPackFiltId())
							removeId[info.GetPackFiltId()] = true
						}
						result := []models.FlowInformation{}
						for _, info := range rule.FlowInfos {
							if _, exist := removeId[info.GetPackFiltId()]; !exist {
								result = append(result, info)
							}
						}
						rule.FlowInfos = result
					}
					smPolicyDecision.PccRules[req.GetPccRuleId()] = rule
				} else {
					errCause = fmt.Sprintf("can not find the pccRuleId[%s] in Session[%d]", req.GetPccRuleId(), smPolicyContext.GetPduSessionId())
				}
			}

		case models.POLICYCONTROLREQUESTTRIGGER_AC_TY_CH: // UE Access Type Change (subsclause 4.2.4.8 in TS29512)
			if request.GetAccessType() == "" {
				errCause = "Access Type is empty in Trigger AC_TY_CH"
				break
			}
			// if request.AccessType == models.AccessType__3_GPP_ACCESS && smPolicyContext.Var3gppPsDataOffStatus {
			// TODO: Handle Data off Status
			// Block Session Service except for Exempt Serice which is described in TS22011, TS 23221
			// }
			smPolicyContext.AccessType = request.AccessType
			afEventsNotification.AccessType = request.AccessType
			if request.GetRatType() != "" {
				smPolicyContext.RatType = request.RatType
				afEventsNotification.RatType = request.RatType
			}
			afNotif := models.AfEventNotification{
				Event: models.AFEVENTPCF_ACCESS_TYPE_CHANGE,
			}
			afEventsNotification.EvNotifs = append(afEventsNotification.EvNotifs, afNotif)
			logger.SMpolicylog.Debugf("SM Policy Update(%s) Successfully", trigger)
		case models.POLICYCONTROLREQUESTTRIGGER_UE_IP_CH: // SMF notice PCF "ipv4Address" & ipv6AddressPrefix (always)
			// TODO: Decide new Session Rule / Pcc rule
			if request.RelIpv4Address == smPolicyContext.Ipv4Address {
				smPolicyContext.Ipv4Address = openapi.PtrString("")
			}
			if request.RelIpv6AddressPrefix == smPolicyContext.Ipv6AddressPrefix {
				smPolicyContext.Ipv6AddressPrefix = openapi.PtrString("")
			}
			if request.GetIpv4Address() != "" {
				smPolicyContext.Ipv4Address = request.Ipv4Address
			}
			if request.GetIpv6AddressPrefix() != "" {
				smPolicyContext.Ipv6AddressPrefix = request.Ipv6AddressPrefix
			}
			logger.SMpolicylog.Debugf("SM Policy Update(%s) Successfully", trigger)
		case models.POLICYCONTROLREQUESTTRIGGER_UE_MAC_CH: // SMF notice PCF when SMF detect new UE MAC
		case models.POLICYCONTROLREQUESTTRIGGER_AN_CH_COR:
		// Access Network Charging Correlation Info (subsclause 4.2.6.5.1, 4.2.4.13 in TS29512)
		// request.AccNetChIds
		case models.POLICYCONTROLREQUESTTRIGGER_US_RE: // UMC (subsclause 4.2.4.10, 5.8 in TS29512)
			afNotif := models.AfEventNotification{
				Event: models.AFEVENTPCF_USAGE_REPORT,
			}
			afEventsNotification.EvNotifs = append(afEventsNotification.EvNotifs, afNotif)
		case models.POLICYCONTROLREQUESTTRIGGER_APP_STA: // ADC (subsclause 4.2.4.6, 5.8 in TS29512)
			// request.AppDetectionInfos
		case models.POLICYCONTROLREQUESTTRIGGER_APP_STO: // ADC (subsclause 4.2.4.6, 5.8 in TS29512)
			// request.AppDetectionInfos
		case models.POLICYCONTROLREQUESTTRIGGER_AN_INFO: // NetLoc (subsclause 4.2.4.9, 5.8 in TS29512)
		case models.POLICYCONTROLREQUESTTRIGGER_CM_SES_FAIL: // Credit Management Session Failure
			// request.CreditManageStatus
		case models.POLICYCONTROLREQUESTTRIGGER_PS_DA_OFF:
			// 3GPP PS Data Off status changed (subsclause 4.2.4.8, 5.8 in TS29512) (always)
			if smPolicyContext.Var3gppPsDataOffStatus != request.Var3gppPsDataOffStatus {
				// TODO: Handle Data off Status
				// if request.Var3gppPsDataOffStatus {
				// Block Session Service except for Exempt Serice which is described in TS22011, TS 23221
				// } else {
				// UnBlock Session Service
				// }
				smPolicyContext.Var3gppPsDataOffStatus = request.Var3gppPsDataOffStatus
			}
		case models.POLICYCONTROLREQUESTTRIGGER_DEF_QOS_CH:
			// Default QoS Change (subsclause 4.2.4.5 in TS29512) (always)
			if request.SubsDefQos == nil {
				errCause = "SubsDefQos  is nil in Trigger DEF_QOS_CH"
				break
			}
			smPolicyContext.SubsDefQos = request.SubsDefQos
			sessRuleId := fmt.Sprintf("SessRuleId-%d", smPolicyContext.PduSessionId)
			if smPolicyDecision.GetSessRules()[sessRuleId].AuthDefQos == nil {
				tmp := smPolicyDecision.GetSessRules()[sessRuleId]
				tmp.AuthDefQos = models.NewAuthorizedDefaultQos()
				(*smPolicyDecision.SessRules)[sessRuleId] = tmp
			}
			authQos := smPolicyDecision.GetSessRules()[sessRuleId].AuthDefQos
			authQos.Var5qi = openapi.PtrInt32(request.SubsDefQos.Var5qi)
			authQos.Arp = &request.SubsDefQos.Arp
			authQos.PriorityLevel = *openapi.NewNullableInt32(request.SubsDefQos.PriorityLevel)
			logger.SMpolicylog.Debugf("SM Policy Update(%s) Successfully", trigger)
		case models.POLICYCONTROLREQUESTTRIGGER_SE_AMBR_CH: // Session Ambr Change (subsclause 4.2.4.4 in TS29512) (always)
			if request.SubsSessAmbr == nil {
				errCause = "SubsSessAmbr  is nil in Trigger SE_AMBR_CH"
				break
			}
			smPolicyContext.SubsSessAmbr = request.SubsSessAmbr
			sessRuleId := fmt.Sprintf("SessRuleId-%d", smPolicyContext.PduSessionId)
			if smPolicyDecision.GetSessRules()[sessRuleId].AuthSessAmbr == nil {
				tmp := smPolicyDecision.GetSessRules()[sessRuleId]
				tmp.AuthSessAmbr = models.NewAmbrWithDefaults()
				(*smPolicyDecision.SessRules)[sessRuleId] = tmp
			}
			sessRule := (*smPolicyDecision.SessRules)[sessRuleId]
			sessRule.AuthSessAmbr = request.SubsSessAmbr
			(*smPolicyDecision.SessRules)[sessRuleId] = sessRule
			logger.SMpolicylog.Debugf("SM Policy Update(%s) Successfully", trigger)
		case models.POLICYCONTROLREQUESTTRIGGER_QOS_NOTIF:
			// SMF notify PCF when receiving from RAN that QoS can/can't be guaranteed (subsclause 4.2.4.20 in TS29512) (always)
			// request.QncReports
			afNotif := models.AfEventNotification{
				Event: models.AFEVENTPCF_QOS_NOTIF,
			}
			afEventsNotification.EvNotifs = append(afEventsNotification.EvNotifs, afNotif)
			afEventsNotification.QncReports = request.QncReports
		case models.POLICYCONTROLREQUESTTRIGGER_NO_CREDIT: // Out of Credit
		case models.POLICYCONTROLREQUESTTRIGGER_PRA_CH: // Presence Reporting (subsclause 4.2.6.5.6, 4.2.4.16, 5.8 in TS29512)
			// request.RepPraInfos
		case models.POLICYCONTROLREQUESTTRIGGER_SAREA_CH: // Change Of Service Area
			if request.UserLocationInfo == nil {
				errCause = "UserLocationInfo  is nil in Trigger SAREA_CH"
				break
			}
			smPolicyContext.UserLocationInfo = request.UserLocationInfo
			logger.SMpolicylog.Debugf("SM Policy Update(%s) Successfully", trigger)
		case models.POLICYCONTROLREQUESTTRIGGER_SCNN_CH: // Change of Serving Network Function
			if request.ServNfId == nil {
				errCause = "ServNfId  is nil in Trigger SCNN_CH"
				break
			}
			smPolicyContext.ServNfId = request.ServNfId
			logger.SMpolicylog.Debugf("SM Policy Update(%s) Successfully", trigger)
		case models.POLICYCONTROLREQUESTTRIGGER_RE_TIMEOUT: // Revalidation TimeOut (subsclause 4.2.4.13 in TS29512)
			// formatTimeStr := time.Now()
			// formatTimeStr = formatTimeStr.Add(time.Second * 60)
			// formatTimeStrAdd := formatTimeStr.Format(pcfContext.GetTimeformat())
			// formatTime, err := time.Parse(pcfContext.GetTimeformat(), formatTimeStrAdd)
			// if err == nil {
			// 	smPolicyDecision.RevalidationTime = &formatTime
			// }
		case models.POLICYCONTROLREQUESTTRIGGER_RES_RELEASE:
			// Outcome of request Pcc rule removal (subsclause 4.2.6.5.2, 5.8 in TS29512)
		case models.POLICYCONTROLREQUESTTRIGGER_SUCC_RES_ALLO:
			// Successful resource allocation (subsclause 4.2.6.5.5, 4.2.4.14 in TS29512)
			afNotif := models.AfEventNotification{
				Event: models.AFEVENTPCF_SUCCESSFUL_RESOURCES_ALLOCATION,
			}
			afEventsNotification.EvNotifs = append(afEventsNotification.EvNotifs, afNotif)
		case models.POLICYCONTROLREQUESTTRIGGER_RAT_TY_CH: // Change of RatType
			if request.GetRatType() == "" {
				errCause = "RatType is empty in Trigger RAT_TY_CH"
				break
			}
			smPolicyContext.RatType = request.RatType
			logger.SMpolicylog.Debugf("SM Policy Update(%s) Successfully", trigger)
		case models.POLICYCONTROLREQUESTTRIGGER_REF_QOS_IND_CH: // Change of reflective Qos Indication from UE
			smPolicyContext.RefQosIndication = request.RefQosIndication
			// TODO: modify Decision about RefQos in Pcc rule
			logger.SMpolicylog.Debugf("SM Policy Update(%s) Successfully", trigger)
		case models.POLICYCONTROLREQUESTTRIGGER_NUM_OF_PACKET_FILTER: // Interworking Only (always)
		case models.POLICYCONTROLREQUESTTRIGGER_UE_STATUS_RESUME: // UE State Resume
			// TODO
		case models.POLICYCONTROLREQUESTTRIGGER_UE_TZ_CH: // UE TimeZome Change
			if request.GetUeTimeZone() == "" {
				errCause = "Ue TimeZone is empty in Trigger UE_TZ_CH"
				break
			}
			smPolicyContext.UeTimeZone = request.UeTimeZone
			logger.SMpolicylog.Debugf("SM Policy Update(%s) Successfully", trigger)
		}
	}

	var successRules, failRules []models.RuleReport
	for _, rule := range request.RuleReports {
		if rule.RuleStatus == models.RULESTATUS_ACTIVE {
			successRules = append(successRules, rule)
		} else {
			failRules = append(failRules, rule)
			// release fail pccRules in SmPolicy
			for _, pccRuleID := range rule.PccRuleIds {
				if err := smPolicy.RemovePccRule(pccRuleID, nil); err != nil {
					logger.SMpolicylog.Warnf(
						"SM Policy Notification about failed installing PccRule[%s]", err.Error())
				}
			}
		}
	}
	if len(failRules) > 0 {
		afNotif := models.AfEventNotification{
			Event: models.AFEVENTPCF_FAILED_RESOURCES_ALLOCATION,
		}
		afEventsNotification.EvNotifs = append(afEventsNotification.EvNotifs, afNotif)
	}
	if afEventsNotification.EvNotifs != nil {
		sendSmPolicyRelatedAppSessionNotification(
			smPolicy, afEventsNotification, request.AccuUsageReports, successRules, failRules)
	}

	if errCause != "" {
		problemDetail := util.GetProblemDetail(errCause, util.ERROR_TRIGGER_EVENT)
		logger.SMpolicylog.Warnln(errCause)
		return nil, problemDetail
	}
	logger.SMpolicylog.Debugf("SMPolicy smPolicyID[%s] Update", smPolicyID)
	// message.SendHttpResponseMessage(httpChannel, nil, http.StatusOK, *smPolicyDecision)
	return smPolicyDecision, nil
}

func sendSmPolicyRelatedAppSessionNotification(smPolicy *pcfContext.UeSmPolicyData,
	notification models.EventsNotification, usageReports []models.AccuUsageReport,
	successRules, failRules []models.RuleReport,
) {
	for appSessionId := range smPolicy.AppSessions {
		if val, exist := pcfContext.PCF_Self().AppSessionPool.Load(appSessionId); exist {
			appSession := val.(*pcfContext.AppSessionData)
			if len(appSession.Events) == 0 {
				continue
			}
			sessionNotif := models.EventsNotification{}
			for _, notif := range notification.EvNotifs {
				if _, found := appSession.Events[notif.Event]; found {
					switch notif.Event {
					case models.AFEVENTPCF_ACCESS_TYPE_CHANGE:
						sessionNotif.AccessType = notification.AccessType
						sessionNotif.RatType = notification.RatType
					case models.AFEVENTPCF_FAILED_RESOURCES_ALLOCATION:
						failItem := models.ResourcesAllocationInfo{
							McResourcStatus: models.MEDIACOMPONENTRESOURCESSTATUS_INACTIVE.Ptr(),
						}
						flows := make(map[int32]models.Flows)
						for _, report := range failRules {
							for _, pccRuleId := range report.PccRuleIds {
								if key, exist := appSession.PccRuleIdMapToCompId[pccRuleId]; exist {
									items := strings.Split(key, "-")
									if items[0] != "appId" {
										compN, err := strconv.Atoi(items[0])
										if err != nil {
											logger.SMpolicylog.Errorf("strconv Atoi error %+v", err)
										}
										compN32 := int32(compN)
										if len(items) == 1 {
											// Comp
											flow := models.Flows{
												MedCompN: compN32,
											}
											failItem.Flows = append(failItem.Flows, flow)
										} else if len(items) == 2 {
											// have subComp
											fNum, err := strconv.Atoi(items[1])
											if err != nil {
												logger.SMpolicylog.Errorf("strconv Atoi error %+v", err)
											}
											fNum32 := int32(fNum)

											flow, exist := flows[compN32]
											if !exist {
												flow = models.Flows{
													MedCompN: compN32,
													FNums:    []int32{fNum32},
												}
											} else {
												flow.FNums = append(flow.FNums, fNum32)
											}
											flows[compN32] = flow
										}
									}
									// Release related resource
									delete(appSession.PccRuleIdMapToCompId, pccRuleId)
									delete(appSession.RelatedPccRuleIds, key)
								}
							}
						}
						for _, flow := range flows {
							failItem.Flows = append(failItem.Flows, flow)
						}
						if failItem.Flows != nil {
							sessionNotif.FailedResourcAllocReports = append(sessionNotif.FailedResourcAllocReports, failItem)
						} else {
							continue
						}
					case models.AFEVENTPCF_PLMN_CHG:
						sessionNotif.PlmnId = notification.PlmnId
					case models.AFEVENTPCF_QOS_NOTIF:
						for _, report := range sessionNotif.QncReports {
							for _, pccRuleId := range report.RefPccRuleIds {
								if _, exist := appSession.PccRuleIdMapToCompId[pccRuleId]; exist {
									sessionNotif.QncReports = append(sessionNotif.QncReports, report)
									break
								}
							}
						}
						if sessionNotif.QncReports == nil {
							continue
						}
					case models.AFEVENTPCF_SUCCESSFUL_RESOURCES_ALLOCATION:
						// Subscription to resources allocation outcome
						if successRules == nil {
							continue
						}
						flows := make(map[int32]models.Flows)
						for _, report := range successRules {
							for _, pccRuleId := range report.PccRuleIds {
								if key, exist := appSession.PccRuleIdMapToCompId[pccRuleId]; exist {
									items := strings.Split(key, "-")
									if items[0] != "appId" {
										compN, err := strconv.Atoi(items[0])
										if err != nil {
											logger.SMpolicylog.Errorf("strconv Atoi error %+v", err)
										}
										compN32 := int32(compN)
										if len(items) == 1 {
											// Comp
											flow := models.Flows{
												MedCompN: compN32,
											}
											notif.Flows = append(notif.Flows, flow)
										} else if len(items) == 2 {
											// have subComp
											fNum, err := strconv.Atoi(items[1])
											if err != nil {
												logger.SMpolicylog.Errorf("strconv Atoi error %+v", err)
											}
											fNum32 := int32(fNum)
											flow, exist := flows[compN32]
											if !exist {
												flow = models.Flows{
													MedCompN: compN32,
													FNums:    []int32{fNum32},
												}
											} else {
												flow.FNums = append(flow.FNums, fNum32)
											}
											flows[compN32] = flow
										}
									}
								}
							}
						}
						for _, flow := range flows {
							notif.Flows = append(notif.Flows, flow)
						}
						if notif.Flows == nil {
							continue
						}
					case models.AFEVENTPCF_USAGE_REPORT:
						for _, report := range usageReports {
							for _, pccRuleId := range appSession.RelatedPccRuleIds {
								if pccRule, exist := appSession.SmPolicyData.PolicyDecision.PccRules[pccRuleId]; exist {
									if pccRule.RefUmData != nil && pccRule.RefUmData[0] == report.RefUmIds {
										sessionNotif.UsgRep = &models.AccumulatedUsage{
											Duration:       report.TimeUsage,
											TotalVolume:    report.VolUsage,
											UplinkVolume:   report.VolUsageUplink,
											DownlinkVolume: report.VolUsageDownlink,
										}
										break
									}
								}
							}
							if sessionNotif.UsgRep != nil {
								sessionNotif.EvNotifs = append(sessionNotif.EvNotifs, notif)
								break
							}
						}
						fallthrough
					default:
						continue
					}
					sessionNotif.EvNotifs = append(sessionNotif.EvNotifs, notif)
				}
			}
			if sessionNotif.EvNotifs != nil {
				SendAppSessionEventNotification(appSession, sessionNotif)
			}
		}
	}
}
