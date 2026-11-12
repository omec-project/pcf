// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"fmt"

	"github.com/omec-project/openapi/v2/models"
)

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
