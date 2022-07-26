// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package producer

import (
	"net/http"

	"github.com/omec-project/http_wrapper"
	"github.com/omec-project/openapi/models"
	"github.com/omec-project/pcf/logger"
)

func HandleAmfStatusChangeNotify(request *http_wrapper.Request) *http_wrapper.Response {
	logger.CallbackLog.Warnf("[PCF] Handle Amf Status Change Notify is not implemented.")

	notification := request.Body.(models.AmfStatusChangeNotification)

	AmfStatusChangeNotifyProcedure(notification)

	return http_wrapper.NewResponse(http.StatusNoContent, nil, nil)
}

// TODO: handle AMF Status Change Notify
func AmfStatusChangeNotifyProcedure(notification models.AmfStatusChangeNotification) {
	logger.CallbackLog.Debugf("receive AMF status change notification[%+v]", notification)
}

func HandleSmPolicyNotify(request *http_wrapper.Request) *http_wrapper.Response {
	logger.CallbackLog.Warnf("[PCF] Handle Sm Policy Notify is not implemented.")

	notification := request.Body.(models.PolicyDataChangeNotification)
	supi := request.Params["ReqURI"]

	SmPolicyNotifyProcedure(supi, notification)

	return http_wrapper.NewResponse(http.StatusNotImplemented, nil, nil)
}

// TODO: handle SM Policy Notify
func SmPolicyNotifyProcedure(supi string, notification models.PolicyDataChangeNotification) {
}
