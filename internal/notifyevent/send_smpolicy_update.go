// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package notifyevent

import (
	"context"
	"net/http"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/pcf/logger"
	"github.com/omec-project/pcf/util"
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
	client := util.GetNpcfSMPolicyCallbackClient()
	logger.NotifyEventLog.Infoln("send SM Policy Update Notification to SMF")
	_, httpResponse, err := client.DefaultCallbackApi.SmPolicyUpdateNotification(context.Background(), e.uri, *e.request)
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

// HandleEvent implements the EventHandler interface for the dispatcher
func (e SendSMpolicyUpdateNotifyEvent) HandleEvent(eventName string, data any) error {
	// This method is called by the dispatcher
	e.Handle()
	return nil
}

// NewSendSMpolicyUpdateNotifyEvent creates a new update notification event
func NewSendSMpolicyUpdateNotifyEvent(uri string, request *models.SmPolicyNotification) SendSMpolicyUpdateNotifyEvent {
	return SendSMpolicyUpdateNotifyEvent{
		uri:     uri,
		request: request,
	}
}
