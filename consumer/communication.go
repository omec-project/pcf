// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package consumer

import (
	"context"
	"fmt"
	"strings"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/Namf_Communication"
	"github.com/omec-project/openapi/v2/models"
	pcf_context "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/logger"
)

func AmfStatusChangeSubscribe(amfUri string, guamiList []models.Guami) (
	problemDetails *models.ProblemDetails, err error,
) {
	logger.Consumerlog.Debugf("PCF Subscribe to AMF status[%+v]", amfUri)
	pcfSelf := pcf_context.PCF_Self()
	configuration := Namf_Communication.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = amfUri
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	client := Namf_Communication.NewAPIClient(configuration)

	subscriptionDataAmf := models.SubscriptionDataAmf{
		AmfStatusUri: fmt.Sprintf("%s/npcf-callback/v1/amfstatus", pcfSelf.GetIPv4Uri()),
		GuamiList:    guamiList,
	}

	apiAMFStatusChangeSubscribeRequest := client.SubscriptionsCollectionCollectionAPI.AMFStatusChangeSubscribe(context.Background())
	apiAMFStatusChangeSubscribeRequest = apiAMFStatusChangeSubscribeRequest.SubscriptionDataAmf(subscriptionDataAmf)
	res, httpResp, localErr := client.SubscriptionsCollectionCollectionAPI.AMFStatusChangeSubscribeExecute(apiAMFStatusChangeSubscribeRequest)
	if localErr == nil {
		locationHeader := httpResp.Header.Get("Location")
		logger.Consumerlog.Debugf("location header: %+v", locationHeader)

		subscriptionID := locationHeader[strings.LastIndex(locationHeader, "/")+1:]
		amfStatusSubsData := pcf_context.AMFStatusSubscriptionData{
			AmfUri:       amfUri,
			AmfStatusUri: res.AmfStatusUri,
			GuamiList:    res.GuamiList,
		}
		pcfSelf.NewAmfStatusSubscription(subscriptionID, amfStatusSubsData)
	} else if httpResp != nil {
		// ErrorModel accepts the model whether the client stored it by value or by pointer, and
		// reports whether there was one. The unchecked assertion this replaces asked for the
		// value type - the client returns *GenericOpenAPIError - so reaching it panicked rather
		// than reading the model. The removed status guard is what kept it out of reach, and only
		// for a response the client has an arm for: a status it does not name leaves RawError
		// equal to the status, which passed the guard straight into the panic.
		if problem, ok := openapi.ErrorModel[models.ProblemDetails](localErr); ok {
			problemDetails = &problem
		} else {
			err = localErr
		}
	} else {
		err = openapi.ReportError("%s: server no response", amfUri)
	}

	defer func() {
		// httpResp can be nil in some error scenarios above; this check prevents a
		// panic when accessing httpResp.Body
		if httpResp != nil {
			// Deliberately not the named err: a successful close returns nil, and assigning
			// that would report success for a subscribe the AMF had refused. Unobservable
			// before, because the guard removed above returned before this ran.
			if closeErr := httpResp.Body.Close(); closeErr != nil {
				logger.Consumerlog.Errorf("error closing response body: %v", closeErr)
			}
		}
	}()

	return problemDetails, err
}
