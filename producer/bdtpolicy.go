// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package producer

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/mohae/deepcopy"
	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/Nnrf_NFDiscovery"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
	"github.com/omec-project/pcf/consumer"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/logger"
	"github.com/omec-project/pcf/util"
	"github.com/omec-project/util/httpwrapper"
)

func HandleGetBDTPolicyContextRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.Bdtpolicylog.Infoln("handle GetBDTPolicyContext")
	bdtPolicyID := request.Params["bdtPolicyId"]
	response, problemDetails := getBDTPolicyContextProcedure(bdtPolicyID)
	if response != nil {
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getBDTPolicyContextProcedure(bdtPolicyID string) (
	response *models.BdtPolicy, problemDetails *models.ProblemDetails,
) {
	logger.Bdtpolicylog.Debugln("handle BDT Policy GET")
	// check bdtPolicyID from pcfUeContext
	if value, ok := pcfContext.PCF_Self().BdtPolicyPool.Load(bdtPolicyID); ok {
		bdtPolicy := value.(*models.BdtPolicy)
		return bdtPolicy, nil
	} else {
		// not found
		problemDetail := util.GetProblemDetail("Can't find bdtPolicyID related resource", util.CONTEXT_NOT_FOUND)
		logger.Bdtpolicylog.Warnln(problemDetail.GetDetail())
		return nil, problemDetail
	}
}

// HandleUpdateBDTPolicyContextProcedure Update an Individual BDT policy (choose policy data)
func HandleUpdateBDTPolicyContextProcedure(request *httpwrapper.Request) *httpwrapper.Response {
	logger.Bdtpolicylog.Infoln("handle UpdateBDTPolicyContext")
	requestDataType := request.Body.(models.BdtPolicyDataPatch)
	bdtPolicyID := request.Params["bdtPolicyId"]
	response, problemDetails := updateBDTPolicyContextProcedure(requestDataType, bdtPolicyID)
	if response != nil {
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func updateBDTPolicyContextProcedure(request models.BdtPolicyDataPatch, bdtPolicyID string) (
	response *models.BdtPolicy, problemDetails *models.ProblemDetails,
) {
	logger.Bdtpolicylog.Infoln("handle BDTPolicyUpdate")
	// check bdtPolicyID from pcfUeContext
	pcfSelf := pcfContext.PCF_Self()

	var bdtPolicy *models.BdtPolicy
	if value, ok := pcfContext.PCF_Self().BdtPolicyPool.Load(bdtPolicyID); ok {
		bdtPolicy = value.(*models.BdtPolicy)
	} else {
		// not found
		problemDetail := util.GetProblemDetail("Can't find bdtPolicyID related resource", util.CONTEXT_NOT_FOUND)
		logger.Bdtpolicylog.Warnln(problemDetail.GetDetail())
		return nil, problemDetail
	}

	for _, policy := range bdtPolicy.BdtPolData.TransfPolicies {
		if policy.TransPolicyId == request.SelTransPolicyId {
			polData := bdtPolicy.BdtPolData
			polReq := bdtPolicy.BdtReqData
			polData.SelTransPolicyId = openapi.PtrInt32(request.SelTransPolicyId)
			bdtData := models.BdtData{
				AspId:       polReq.AspId,
				TransPolicy: policy,
				BdtRefId:    openapi.PtrString(polData.BdtRefId),
			}
			if polReq.NwAreaInfo != nil {
				bdtData.NwAreaInfo = polReq.NwAreaInfo
			}
			client := util.GetNudrClient(getDefaultUdrUri(pcfSelf))
			apiCreateIndividualBdtDataRequest := client.IndividualBdtDataDocumentAPI.CreateIndividualBdtData(context.Background(), bdtData.GetBdtRefId())
			apiCreateIndividualBdtDataRequest = apiCreateIndividualBdtDataRequest.BdtData(bdtData)
			_, rsp, err := client.IndividualBdtDataDocumentAPI.CreateIndividualBdtDataExecute(apiCreateIndividualBdtDataRequest)
			if err != nil {
				logger.Bdtpolicylog.Warnf("put BdtData error[%s]", err.Error())
			}
			if rsp != nil && rsp.Body != nil {
				defer func() {
					if rspCloseErr := rsp.Body.Close(); rspCloseErr != nil {
						logger.Bdtpolicylog.Errorf("PolicyDataBdtDataBdtReferenceIdPut response body cannot close: %+v", rspCloseErr)
					}
				}()
			}
			logger.Bdtpolicylog.Debugf("bdtPolicyID[%s] has Updated with SelTransPolicyId[%d]",
				bdtPolicyID, request.SelTransPolicyId)
			return bdtPolicy, nil
		}
	}
	problemDetail := util.GetProblemDetail(
		fmt.Sprintf("Can't find TransPolicyId[%d] in TransfPolicies with bdtPolicyID[%s]",
			request.SelTransPolicyId, bdtPolicyID),
		util.CONTEXT_NOT_FOUND)
	logger.Bdtpolicylog.Warnln(problemDetail.GetDetail())
	return nil, problemDetail
}

// HandleCreateBDTPolicyContextRequest Create a new Individual BDT policy
func HandleCreateBDTPolicyContextRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.Bdtpolicylog.Infoln("handle CreateBDTPolicyContext")
	requestMsg := request.Body.(models.BdtReqData)
	header, response, problemDetails := createBDTPolicyContextProcedure(&requestMsg)
	if response != nil {
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusCreated, header, response)
	} else if problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	} else {
		return httpwrapper.NewResponse(http.StatusNotFound, nil, nil)
	}
}

func createBDTPolicyContextProcedure(request *models.BdtReqData) (
	header http.Header, response *models.BdtPolicy, problemDetails *models.ProblemDetails,
) {
	response = &models.BdtPolicy{}
	logger.Bdtpolicylog.Debugln("handle BDT Policy Create")

	pcfSelf := pcfContext.PCF_Self()
	udrUri := getDefaultUdrUri(pcfSelf)
	if udrUri == "" {
		// Can't find any UDR support this Ue
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusServiceUnavailable)
		problemDetails.SetCause("UDR_NOT_FOUND")
		problemDetails.SetDetail("Cannot find any UDR that supports this PCF")
		logger.Bdtpolicylog.Warnln(problemDetails.GetDetail())
		return nil, nil, problemDetails
	}
	pcfSelf.SetDefaultUdrURI(udrUri)

	// Query BDT DATA array from UDR
	client := util.GetNudrClient(udrUri)
	apiReadBdtDataRequest := client.BdtDataStoreAPI.ReadBdtData(context.Background())
	bdtDatas, httpResponse, err := client.BdtDataStoreAPI.ReadBdtDataExecute(apiReadBdtDataRequest)
	if err != nil || httpResponse == nil || httpResponse.StatusCode != http.StatusOK {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusServiceUnavailable)
		problemDetails.SetCause("UDR_QUERY_FAILED")
		if err != nil {
			problemDetails.SetDetail(err.Error())
		} else if httpResponse == nil {
			problemDetails.SetDetail("Query to UDR failed: no response")
		} else {
			problemDetails.SetDetail(fmt.Sprintf("Query to UDR failed: unexpected status %s", httpResponse.Status))
		}
		logger.Bdtpolicylog.Warnln("query to UDR failed")
		return nil, nil, problemDetails
	}
	defer func() {
		if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
			logger.Bdtpolicylog.Errorf("PolicyDataBdtDataGet response body cannot close: %+v", rspCloseErr)
		}
	}()
	// TODO: decide BDT Policy from other bdt policy data
	response.BdtReqData = deepcopy.Copy(&request).(*models.BdtReqData)
	var bdtData *models.BdtData
	var bdtPolicyData models.BdtPolicyData
	for _, data := range bdtDatas {
		// If ASP has exist, use its background data policy
		if request.AspId == data.AspId {
			bdtData = &data
			break
		}
	}
	// Only support one bdt policy, TODO: more policy for decision
	if bdtData != nil {
		// found
		// modify policy according to new request
		bdtData.TransPolicy.RecTimeInt = request.DesTimeInt
	} else {
		// use default bdt policy, TODO: decide bdt transfer data policy
		bdtData = &models.BdtData{
			AspId:       request.AspId,
			BdtRefId:    openapi.PtrString(uuid.New().String()),
			TransPolicy: getDefaultTransferPolicy(1, request.DesTimeInt),
		}
	}
	if request.NwAreaInfo != nil {
		bdtData.NwAreaInfo = request.NwAreaInfo
	}
	bdtPolicyData.SelTransPolicyId = openapi.PtrInt32(bdtData.TransPolicy.TransPolicyId)
	// no support feature in subclause 5.8 of TS29554
	bdtPolicyData.BdtRefId = bdtData.GetBdtRefId()
	bdtPolicyData.TransfPolicies = append(bdtPolicyData.TransfPolicies, bdtData.TransPolicy)
	response.BdtPolData = &bdtPolicyData
	bdtPolicyID, err := pcfSelf.AllocBdtPolicyID()
	if err != nil {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusServiceUnavailable)
		problemDetails.SetCause("ALLOC_BDT_POLICY_ID_FAILED")
		problemDetails.SetDetail("Allocate bdtPolicyID failed")
		logger.Bdtpolicylog.Warnln("allocate bdtPolicyID failed")
		return nil, nil, problemDetails
	}

	pcfSelf.BdtPolicyPool.Store(bdtPolicyID, response)

	var updateRsp *http.Response
	apiCreateIndividualBdtDataRequest := client.IndividualBdtDataDocumentAPI.CreateIndividualBdtData(context.Background(),
		bdtPolicyData.BdtRefId)
	apiCreateIndividualBdtDataRequest = apiCreateIndividualBdtDataRequest.BdtData(*bdtData)
	_, rsp, rspErr := client.IndividualBdtDataDocumentAPI.CreateIndividualBdtDataExecute(apiCreateIndividualBdtDataRequest)
	if rspErr != nil {
		logger.Bdtpolicylog.Warnf("UDR put BdtData error[%s]", rspErr.Error())
	} else {
		updateRsp = rsp
	}
	defer func() {
		if updateRsp != nil && updateRsp.Body != nil {
			if rspCloseErr := updateRsp.Body.Close(); rspCloseErr != nil {
				logger.Bdtpolicylog.Errorf("PolicyDataBdtDataBdtReferenceIdPut response body cannot close: %+v", rspCloseErr)
			}
		}
	}()

	locationHeader := util.GetResourceUri(models.SERVICENAME_NPCF_BDTPOLICYCONTROL, bdtPolicyID)
	header = http.Header{
		"Location": {locationHeader},
	}
	logger.Bdtpolicylog.Debugf("BDT Policy Id[%s] Create", bdtPolicyID)
	return header, response, problemDetails
}

func getDefaultUdrUri(context *pcfContext.PCFContext) string {
	context.DefaultUdrURILock.RLock()
	defer context.DefaultUdrURILock.RUnlock()
	resp, err := consumer.SendSearchNFInstances(context.NrfUri, models.NFTYPE_UDR, models.NFTYPE_PCF, func(request Nnrf_NFDiscovery.ApiSearchNFInstancesRequest) Nnrf_NFDiscovery.ApiSearchNFInstancesRequest {
		return request.ServiceNames([]models.ServiceName{models.SERVICENAME_NUDR_DR})
	})
	if err != nil {
		return ""
	}
	for _, nfProfile := range resp.NfInstances {
		udruri := util.SearchNFServiceUri(nfProfile, models.SERVICENAME_NUDR_DR, models.NFSERVICESTATUS_REGISTERED)
		if udruri != "" {
			return udruri
		}
	}
	return ""
}

// get default background data transfer policy
func getDefaultTransferPolicy(transferPolicyId int32, timeWindow models.TimeWindow) models.TransferPolicy {
	return models.TransferPolicy{
		TransPolicyId: transferPolicyId,
		RecTimeInt:    timeWindow,
		RatingGroup:   1,
	}
}
