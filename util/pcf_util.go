// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"encoding"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/omec-project/openapi/v2/Nudr_DR"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/pcf/context"
)

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

func GetNudrClient(uri string) *Nudr_DR.APIClient {
	configuration := Nudr_DR.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = uri
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	client := Nudr_DR.NewAPIClient(configuration)
	return client
}

// Return ProblemDetail; errString represents Detail and cause represents Cause.
func GetProblemDetail(errString, cause string) *models.ProblemDetails {
	problemDetails := models.NewProblemDetails()
	problemDetails.SetStatus(PcpErrHttpStatusMap[cause])
	problemDetails.SetDetail(errString)
	problemDetails.SetCause(cause)
	return problemDetails
}

// GetSMPolicyDnnData returns SMPolicyDnnData derived from SmPolicy data which snssai and dnn match
func GetSMPolicyDnnData(data models.SmPolicyData, snssai models.Snssai, dnn string) (result *models.SmPolicyDnnData) {
	if snssai.GetSst() < 0 || snssai.GetSst() > 255 || dnn == "" || data.SmPolicySnssaiData == nil {
		return
	}
	snssaiString := SnssaiModelsToHex(snssai)
	if snssaiData, exist := data.SmPolicySnssaiData[snssaiString]; exist {
		if snssaiData.SmPolicyDnnData == nil {
			return
		}
		if dnnInfo, exist := snssaiData.GetSmPolicyDnnData()[dnn]; exist {
			result = &dnnInfo
			return
		}
	}
	return
}

var serviceUriMap = map[models.ServiceName]string{
	models.SERVICENAME_NPCF_AM_POLICY_CONTROL:   "policies",
	models.SERVICENAME_NPCF_SMPOLICYCONTROL:     "sm-policies",
	models.SERVICENAME_NPCF_BDTPOLICYCONTROL:    "bdtpolicies",
	models.SERVICENAME_NPCF_POLICYAUTHORIZATION: "app-sessions",
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
	return slices.Contains(triggers, reqTrigger)
}

func DeepCopyViaJSON(src, dst any) error {
	data, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dst)
}

func CompareViaJSON(expected, actual any) bool {
	expectedJSON, err1 := json.Marshal(normalizeForJSON(expected))
	actualJSON, err2 := json.Marshal(normalizeForJSON(actual))

	if err1 != nil || err2 != nil {
		return false
	}

	return string(expectedJSON) == string(actualJSON)
}

type normalizedMapEntry struct {
	Key   any
	Value any
}

func normalizeForJSON(value any) any {
	return normalizeReflectValueForJSON(reflect.ValueOf(value))
}

func normalizeReflectValueForJSON(value reflect.Value) any {
	if !value.IsValid() {
		return nil
	}

	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			return nil
		}
		return normalizeReflectValueForJSON(value.Elem())
	case reflect.Struct:
		normalized := make(map[string]any, value.NumField())
		for i := 0; i < value.NumField(); i++ {
			field := value.Type().Field(i)
			if !field.IsExported() {
				continue
			}

			fieldName, omitEmpty, skip := jsonFieldName(field)
			if skip {
				continue
			}

			fieldValue := value.Field(i)
			if omitEmpty && isJSONEmpty(fieldValue) {
				continue
			}

			normalized[fieldName] = normalizeReflectValueForJSON(fieldValue)
		}
		return normalized
	case reflect.Slice, reflect.Array:
		normalized := make([]any, value.Len())
		for i := 0; i < value.Len(); i++ {
			normalized[i] = normalizeReflectValueForJSON(value.Index(i))
		}
		return normalized
	case reflect.Map:
		if value.IsNil() {
			return nil
		}

		if value.Type().Key().Kind() == reflect.String {
			normalized := make(map[string]any, value.Len())
			for _, key := range value.MapKeys() {
				normalized[key.String()] = normalizeReflectValueForJSON(value.MapIndex(key))
			}
			return normalized
		}

		entries := make([]normalizedMapEntry, 0, value.Len())
		for _, key := range value.MapKeys() {
			entries = append(entries, normalizedMapEntry{
				Key:   normalizeReflectValueForJSON(key),
				Value: normalizeReflectValueForJSON(value.MapIndex(key)),
			})
		}

		sort.Slice(entries, func(i, j int) bool {
			return stableJSON(entries[i].Key) < stableJSON(entries[j].Key)
		})

		return entries
	default:
		return value.Interface()
	}
}

func jsonFieldName(field reflect.StructField) (name string, omitEmpty, skip bool) {
	tag := field.Tag.Get("json")
	if tag == "-" {
		return "", false, true
	}

	name = field.Name
	if tag == "" {
		return name, false, false
	}

	parts := strings.Split(tag, ",")
	if parts[0] != "" {
		name = parts[0]
	}
	for _, option := range parts[1:] {
		if option == "omitempty" {
			omitEmpty = true
		}
	}

	return name, omitEmpty, false
}

func isJSONEmpty(value reflect.Value) bool {
	if !value.IsValid() {
		return true
	}

	switch value.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return value.Len() == 0
	case reflect.Bool:
		return !value.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return value.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return value.Float() == 0
	case reflect.Interface, reflect.Pointer:
		return value.IsNil()
	case reflect.Struct:
		if marshaler, ok := value.Interface().(encoding.TextMarshaler); ok {
			text, err := marshaler.MarshalText()
			return err == nil && len(text) == 0
		}
		return value.IsZero()
	default:
		return value.IsZero()
	}
}

func stableJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%#v", value)
	}
	return string(data)
}
