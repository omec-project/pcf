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
	"github.com/tim-ywliu/event"
)

const SendSMpolicyTerminationNotifyEventName event.Name = "SendSMpolicyTerminationNotify"

type SendSMpolicyTerminationNotifyEvent struct {
	request *models.TerminationNotification
	uri     string
}

func (e SendSMpolicyTerminationNotifyEvent) Handle() {
	logger.NotifyEventLog.Infof("Handle SendSMpolicyTerminationNotifyEvent\n")
	if e.uri == "" {
		logger.NotifyEventLog.Warnln("SM Policy Termination Request Notification Error[URI is empty]")
		return
	}
	client := util.GetNpcfSMPolicyCallbackClient()
	logger.NotifyEventLog.Infof("SM Policy Termination Request Notification to SMF")
	rsp, err := client.DefaultCallbackApi.SmPolicyControlTerminationRequestNotification(context.Background(), e.uri, *e.request)
	if err != nil {
		if rsp != nil {
			logger.NotifyEventLog.Warnf("SM Policy Termination Request Notification Error[%s]", rsp.Status)
		} else {
			logger.NotifyEventLog.Warnf("SM Policy Termination Request Notification Error[%s]", err.Error())
		}
		return
	} else if rsp == nil {
		logger.NotifyEventLog.Warnln("SM Policy Termination Request Notification Error[HTTP Response is nil]")
		return
	}
	defer func() {
		if resCloseErr := rsp.Body.Close(); resCloseErr != nil {
			logger.NotifyEventLog.Errorf("NFInstancesStoreApi response body cannot close: %+v", resCloseErr)
		}
	}()
	if rsp.StatusCode != http.StatusNoContent {
		logger.NotifyEventLog.Warnf("SM Policy Termination Request Notification  Failed")
	} else {
		logger.NotifyEventLog.Tracef("SM Policy Termination Request Notification Success")
	}
}
