// SPDX-FileCopyrightText: 2022 Infosys Limited
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package callback

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
	"github.com/omec-project/pcf/consumer"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/logger"
	"github.com/omec-project/pcf/producer"
	"github.com/omec-project/util/httpwrapper"
)

func HTTPNfSubscriptionStatusNotify(c *gin.Context) {
	var nfSubscriptionStatusNotification models.NotificationData

	requestBody, err := c.GetRawData()
	if err != nil {
		logger.CallbackLog.Errorf("get Request Body error: %+v", err)
		problemDetail := utils.ProblemDetailsSystemFailure(err.Error())
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Decode(&nfSubscriptionStatusNotification, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := utils.ProblemDetailsMalformedRequestSyntax(problemDetail)
		logger.CallbackLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, nfSubscriptionStatusNotification)

	rsp := producer.HandleNfSubscriptionStatusNotify(req)

	responseBody, err := openapi.SetBody(rsp.Body, "application/json")
	if err != nil {
		logger.CallbackLog.Errorln(err)
		problemDetails := utils.ProblemDetailsSystemFailure(err.Error())
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else if rsp.Body != nil {
		c.Data(rsp.Status, "application/json", responseBody.Bytes())
		if nfSubscriptionStatusNotification.Event != models.NOTIFICATIONEVENTTYPE_NF_DEREGISTERED {
			return
		}
		nfID := nfSubscriptionStatusNotification.NfProfile.GetNfInstanceId()
		pcfSelf := pcfContext.PCF_Self()
		value, found := pcfSelf.NfStatusSubscriptions.Load(nfID)
		if !found {
			logger.ConsumerLog.Warnf("no subscriptionId found for NF instance %s", nfID)
			return
		}
		subID := value.(string)
		problem, err := consumer.SendRemoveSubscription(subID)
		if err != nil {
			logger.ConsumerLog.Errorf("failed to remove NRF subscription %s: %+v", subID, err)
			return
		}
		if problem != nil {
			logger.ConsumerLog.Warnf("NRF responded with problem while removing %s: %+v", subID, problem)
			return
		}
		pcfSelf.NfStatusSubscriptions.Delete(nfID)
	}
}
