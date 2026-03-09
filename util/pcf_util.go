// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/omec-project/openapi/Namf_Communication"
	"github.com/omec-project/openapi/Npcf_PolicyAuthorization"
	"github.com/omec-project/openapi/Npcf_SMPolicyControl"
	"github.com/omec-project/openapi/Nudr_DataRepository"
	"github.com/omec-project/openapi/models"
	"github.com/omec-project/pcf/context"
)

const TimeFormat = time.RFC3339

// Path of HTTP2 key and log file
var (
	PCF_BASIC_PATH                               = "https://localhost:29507"
	ERROR_REQUEST_PARAMETERS                     = "ERROR_REQUEST_PARAMETERS"
	USER_UNKNOWN                                 = "USER_UNKNOWN"
	CONTEXT_NOT_FOUND                            = "CONTEXT_NOT_FOUND"
	ERROR_INITIAL_PARAMETERS                     = "ERROR_INITIAL_PARAMETERS"
	POLICY_CONTEXT_DENIED                        = "POLICY_CONTEXT_DENIED"
	ERROR_TRIGGER_EVENT                          = "ERROR_TRIGGER_EVENT"
	ERROR_TRAFFIC_MAPPING_INFO_REJECTED          = "ERROR_TRAFFIC_MAPPING_INFO_REJECTED"
	BDT_POLICY_NOT_FOUND                         = "BDT_POLICY_NOT_FOUND"
	REQUESTED_SERVICE_NOT_AUTHORIZED             = "REQUESTED_SERVICE_NOT_AUTHORIZED"
	REQUESTED_SERVICE_TEMPORARILY_NOT_AUTHORIZED = "REQUESTED_SERVICE_TEMPORARILY_NOT_AUTHORIZED" // NWDAF
	UNAUTHORIZED_SPONSORED_DATA_CONNECTIVITY     = "UNAUTHORIZED_SPONSORED_DATA_CONNECTIVITY"
	PDU_SESSION_NOT_AVAILABLE                    = "PDU_SESSION_NOT_AVAILABLE"
	APPLICATION_SESSION_CONTEXT_NOT_FOUND        = "APPLICATION_SESSION_CONTEXT_NOT_FOUND"
	PcpErrHttpStatusMap                          = map[string]int32{
		ERROR_REQUEST_PARAMETERS:                     http.StatusBadRequest,
		USER_UNKNOWN:                                 http.StatusBadRequest,
		ERROR_INITIAL_PARAMETERS:                     http.StatusBadRequest,
		ERROR_TRIGGER_EVENT:                          http.StatusBadRequest,
		POLICY_CONTEXT_DENIED:                        http.StatusForbidden,
		ERROR_TRAFFIC_MAPPING_INFO_REJECTED:          http.StatusForbidden,
		REQUESTED_SERVICE_NOT_AUTHORIZED:             http.StatusForbidden,
		REQUESTED_SERVICE_TEMPORARILY_NOT_AUTHORIZED: http.StatusForbidden,
		UNAUTHORIZED_SPONSORED_DATA_CONNECTIVITY:     http.StatusForbidden,
		CONTEXT_NOT_FOUND:                            http.StatusNotFound,
		BDT_POLICY_NOT_FOUND:                         http.StatusNotFound,
		APPLICATION_SESSION_CONTEXT_NOT_FOUND:        http.StatusNotFound,
		PDU_SESSION_NOT_AVAILABLE:                    http.StatusInternalServerError,
	}
)

func GetNpcfSMPolicyCallbackClient() *Npcf_SMPolicyControl.APIClient {
	configuration := Npcf_SMPolicyControl.NewConfiguration()
	client := Npcf_SMPolicyControl.NewAPIClient(configuration)
	return client
}

func GetNpcfPolicyAuthorizationCallbackClient() *Npcf_PolicyAuthorization.APIClient {
	configuration := Npcf_PolicyAuthorization.NewConfiguration()
	client := Npcf_PolicyAuthorization.NewAPIClient(configuration)
	return client
}

func GetNudrClient(uri string) *Nudr_DataRepository.APIClient {
	configuration := Nudr_DataRepository.NewConfiguration()
	configuration.SetBasePath(uri)
	client := Nudr_DataRepository.NewAPIClient(configuration)
	return client
}

func GetNamfClient(uri string) *Namf_Communication.APIClient {
	configuration := Namf_Communication.NewConfiguration()
	configuration.SetBasePath(uri)
	client := Namf_Communication.NewAPIClient(configuration)
	return client
}

// Return ProblemDatail, errString represent Detail, cause represent Cause of the fields
func GetProblemDetail(errString, cause string) models.ProblemDetails {
	return models.ProblemDetails{
		Status: PcpErrHttpStatusMap[cause],
		Detail: errString,
		Cause:  cause,
	}
}

// GetSMPolicyDnnData returns SMPolicyDnnData derived from SmPolicy data which snssai and dnn match
func GetSMPolicyDnnData(data models.SmPolicyData, snssai *models.Snssai, dnn string) (result *models.SmPolicyDnnData) {
	if snssai == nil || dnn == "" || data.SmPolicySnssaiData == nil {
		return
	}
	snssaiString := SnssaiModelsToHex(*snssai)
	if snssaiData, exist := data.SmPolicySnssaiData[snssaiString]; exist {
		if snssaiData.SmPolicyDnnData == nil {
			return
		}
		if dnnInfo, exist := snssaiData.SmPolicyDnnData[dnn]; exist {
			result = &dnnInfo
			return
		}
	}
	return
}

var serviceUriMap = map[models.ServiceName]string{
	models.ServiceName_NPCF_AM_POLICY_CONTROL:   "policies",
	models.ServiceName_NPCF_SMPOLICYCONTROL:     "sm-policies",
	models.ServiceName_NPCF_BDTPOLICYCONTROL:    "bdtpolicies",
	models.ServiceName_NPCF_POLICYAUTHORIZATION: "app-sessions",
}

// Get Resource Uri (location Header) with param id string
func GetResourceUri(name models.ServiceName, id string) string {
	return fmt.Sprintf("%s/%s/%s", context.GetUri(name), serviceUriMap[name], id)
}

// Check if Feature is Supported or not
func CheckSuppFeat(suppFeat string, number int) bool {
	bytes, err := hex.DecodeString(suppFeat)
	if err != nil || len(bytes) < 1 {
		return false
	}
	index := len(bytes) - ((number - 1) / 8) - 1
	shift := uint8((number - 1) % 8)
	if index < 0 {
		return false
	}
	if bytes[index]&(0x01<<shift) > 0 {
		return true
	}
	return false
}

func CheckPolicyControlReqTrig(
	triggers []models.PolicyControlRequestTrigger, reqTrigger models.PolicyControlRequestTrigger,
) bool {
	for _, trigger := range triggers {
		if trigger == reqTrigger {
			return true
		}
	}
	return false
}
