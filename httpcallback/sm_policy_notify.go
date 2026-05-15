// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package httpcallback

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
	"github.com/omec-project/pcf/logger"
	"github.com/omec-project/pcf/producer"
	"github.com/omec-project/util/httpwrapper"
)

// Nudr-Notify-smpolicy
func HTTPNudrNotify(c *gin.Context) {
	var policyDataChangeNotification models.PolicyDataChangeNotification

	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := utils.ProblemDetailsSystemFailure(err.Error())
		logger.CallbackLog.Errorf("Get Request Body error: %+v", err)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Decode(&policyDataChangeNotification, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := utils.ProblemDetailsMalformedRequestSyntax(problemDetail)
		logger.CallbackLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, policyDataChangeNotification)
	req.Params["ReqURI"] = c.Params.ByName("supi")

	rsp := producer.HandleSmPolicyNotify(req)

	responseBody, err := openapi.SetBody(rsp.Body, "application/json")
	if err != nil {
		logger.CallbackLog.Errorln(err)
		problemDetails := utils.ProblemDetailsSystemFailure(err.Error())
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, "application/json", responseBody.Bytes())
	}
}
