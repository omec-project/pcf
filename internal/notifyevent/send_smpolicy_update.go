// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package notifyevent

import (
	"context"
	"net/http"

	"github.com/omec-project/openapi/v2/Npcf_SMPolicyControl"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/pcf/logger"
)

const SendSMpolicyUpdateNotifyEventName = "SendSMpolicyUpdateNotify"

type SendSMpolicyUpdateNotifyEvent struct {
	request *models.SmPolicyNotification
	uri     string
}

// Handle processes the SM policy update notification event
func (e SendSMpolicyUpdateNotifyEvent) Handle() {
	logger.NotifyEventLog.Infoln("handle SendSMpolicyUpdateNotifyEvent")
	if e.uri == "" {
		logger.NotifyEventLog.Warnln("SM Policy Update Notification Error [URI is empty]")
		return
	}
	if e.request == nil {
		logger.NotifyEventLog.Warnln("SM Policy Update Notification Error [request is nil]")
		return
	}
	configuration := Npcf_SMPolicyControl.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = e.uri
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	client := Npcf_SMPolicyControl.NewAPIClient(configuration)
	logger.NotifyEventLog.Infoln("send SM Policy Update Notification to SMF")
	apiSmPolicyUpdateNotificationUpdatePostRequest := client.SMPoliciesCollectionCallbackSmPolicyUpdateNotificationAPI.SmPolicyUpdateNotificationUpdatePost(context.Background())
	smPolicyNotification := *e.request
	apiSmPolicyUpdateNotificationUpdatePostRequest = apiSmPolicyUpdateNotificationUpdatePostRequest.SmPolicyNotification(smPolicyNotification)
	_, httpResponse, err := client.SMPoliciesCollectionCallbackSmPolicyUpdateNotificationAPI.SmPolicyUpdateNotificationUpdatePostExecute(apiSmPolicyUpdateNotificationUpdatePostRequest)
	if err != nil {
		if httpResponse != nil {
			logger.NotifyEventLog.Warnf("SM Policy Update Notification Error[%s]", httpResponse.Status)
		} else {
			logger.NotifyEventLog.Warnf("SM Policy Update Notification Failed[%s]", err.Error())
		}
		return
	} else if httpResponse == nil {
		logger.NotifyEventLog.Warnln("SM Policy Update Notification Failed [HTTP Response is nil]")
		return
	}
	defer func() {
		if resCloseErr := httpResponse.Body.Close(); resCloseErr != nil {
			logger.NotifyEventLog.Errorf("NFInstancesStoreApi response body cannot close: %+v", resCloseErr)
		}
	}()
	if httpResponse.StatusCode != http.StatusOK && httpResponse.StatusCode != http.StatusNoContent {
		logger.NotifyEventLog.Warnln("SM Policy Update Notification Failed")
	} else {
		logger.NotifyEventLog.Debugln("SM Policy Update Notification Success")
	}
}
