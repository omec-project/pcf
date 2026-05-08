// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"fmt"

	"github.com/omec-project/openapi/v2/models"
)

var policyTriggerArray = []models.PolicyControlRequestTrigger{
	models.POLICYCONTROLREQUESTTRIGGER_PLMN_CH,
	models.POLICYCONTROLREQUESTTRIGGER_RES_MO_RE,
	models.POLICYCONTROLREQUESTTRIGGER_AC_TY_CH,
	models.POLICYCONTROLREQUESTTRIGGER_UE_IP_CH,
	models.POLICYCONTROLREQUESTTRIGGER_UE_MAC_CH,
	models.POLICYCONTROLREQUESTTRIGGER_AN_CH_COR,
	models.POLICYCONTROLREQUESTTRIGGER_US_RE,
	models.POLICYCONTROLREQUESTTRIGGER_APP_STA,
	models.POLICYCONTROLREQUESTTRIGGER_APP_STO,
	models.POLICYCONTROLREQUESTTRIGGER_AN_INFO,
	models.POLICYCONTROLREQUESTTRIGGER_CM_SES_FAIL,
	models.POLICYCONTROLREQUESTTRIGGER_PS_DA_OFF,
	models.POLICYCONTROLREQUESTTRIGGER_DEF_QOS_CH,
	models.POLICYCONTROLREQUESTTRIGGER_SE_AMBR_CH,
	models.POLICYCONTROLREQUESTTRIGGER_QOS_NOTIF,
	models.POLICYCONTROLREQUESTTRIGGER_NO_CREDIT,
	models.POLICYCONTROLREQUESTTRIGGER_PRA_CH,
	models.POLICYCONTROLREQUESTTRIGGER_SAREA_CH,
	models.POLICYCONTROLREQUESTTRIGGER_SCNN_CH,
	models.POLICYCONTROLREQUESTTRIGGER_RE_TIMEOUT,
	models.POLICYCONTROLREQUESTTRIGGER_RES_RELEASE,
	models.POLICYCONTROLREQUESTTRIGGER_SUCC_RES_ALLO,
	models.POLICYCONTROLREQUESTTRIGGER_RAT_TY_CH,
	models.POLICYCONTROLREQUESTTRIGGER_REF_QOS_IND_CH,
	models.POLICYCONTROLREQUESTTRIGGER_NUM_OF_PACKET_FILTER,
	models.POLICYCONTROLREQUESTTRIGGER_UE_STATUS_RESUME,
	models.POLICYCONTROLREQUESTTRIGGER_UE_TZ_CH,
}

// func GetSMPolicyKey(snssai *models.Snssai, dnn string) string {
// 	if snssai == nil || len(snssai.Sd) != 6 || dnn == "" {
// 		return ""
// 	}
// 	return fmt.Sprintf("%02x%s-%s", snssai.Sst, snssai.Sd, dnn)
// }

// Convert Snssai form models to hexString(sst(2)+sd(6))
func SnssaiModelsToHex(snssai models.Snssai) string {
	sst := fmt.Sprintf("%02x", snssai.Sst)
	return sst + snssai.GetSd()
}

// Use BitMap to generate requested policy control triggers,
// 1 means yes, 0 means no, see subscaulse 5.6.3.6-1 in TS29512
func PolicyControlReqTrigToArray(bitMap uint64) (trigger []models.PolicyControlRequestTrigger) {
	cnt := 0
	size := len(policyTriggerArray)
	for bitMap > 0 && cnt < size {
		if (bitMap & 0x01) > 0 {
			trigger = append(trigger, policyTriggerArray[cnt])
		}
		bitMap >>= 1
		cnt++
	}
	return
}
