// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// SPDX-License-Identifier: Apache-2.0
//

package consumer

import (
	"context"
	"fmt"
	"net/http"

	"github.com/omec-project/openapi/v2/Nnrf_NFDiscovery"
	"github.com/omec-project/openapi/v2/models"
	nrfCache "github.com/omec-project/openapi/v2/nrfcache"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/logger"
	"github.com/omec-project/pcf/util"
)

var (
	CreateSubscription        = SendCreateSubscription
	NRFCacheSearchNFInstances = nrfCache.SearchNFInstances
	StoreApiSearchNFInstances = (*Nnrf_NFDiscovery.NFInstancesStoreAPIService).SearchNFInstancesExecute
)

type SearchNFInstancesRequestConfigurer func(
	Nnrf_NFDiscovery.ApiSearchNFInstancesRequest,
) Nnrf_NFDiscovery.ApiSearchNFInstancesRequest

func buildSearchNFInstancesRequest(
	ctx context.Context,
	client *Nnrf_NFDiscovery.APIClient,
	targetNfType, requestNfType models.NFType,
	configure SearchNFInstancesRequestConfigurer,
) Nnrf_NFDiscovery.ApiSearchNFInstancesRequest {
	request := client.NFInstancesStoreAPI.SearchNFInstances(ctx)
	request = request.TargetNfType(targetNfType)
	request = request.RequesterNfType(requestNfType)
	if configure != nil {
		request = configure(request)
	}
	return request
}

var SendSearchNFInstances = func(nrfUri string, targetNfType, requestNfType models.NFType, configure SearchNFInstancesRequestConfigurer) (
	*models.SearchResult, error,
) {
	ctx := context.Background()
	client := Nnrf_NFDiscovery.NewAPIClient(Nnrf_NFDiscovery.NewConfiguration())
	param := buildSearchNFInstancesRequest(ctx, client, targetNfType, requestNfType, configure)
	if pcfContext.PCF_Self().EnableNrfCaching {
		return NRFCacheSearchNFInstances(ctx, nrfUri, targetNfType, requestNfType, param)
	} else {
		return SendNfDiscoveryToNrf(ctx, nrfUri, targetNfType, requestNfType, param)
	}
}

var SendNfDiscoveryToNrf = func(ctx context.Context, nrfUri string, targetNfType, requestNfType models.NFType, param Nnrf_NFDiscovery.ApiSearchNFInstancesRequest,
) (*models.SearchResult, error) {
	configuration := Nnrf_NFDiscovery.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = nrfUri
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	client := Nnrf_NFDiscovery.NewAPIClient(configuration)

	if param.ApiService == nil {
		param = client.NFInstancesStoreAPI.SearchNFInstances(ctx)
	}
	param = param.TargetNfType(targetNfType)
	param = param.RequesterNfType(requestNfType)
	return executeNfDiscoveryRequest(client, requestNfType, nrfUri, param)
}

func executeNfDiscoveryRequest(
	client *Nnrf_NFDiscovery.APIClient,
	requestNfType models.NFType,
	nrfUri string,
	param Nnrf_NFDiscovery.ApiSearchNFInstancesRequest,
) (*models.SearchResult, error) {
	service, ok := client.NFInstancesStoreAPI.(*Nnrf_NFDiscovery.NFInstancesStoreAPIService)
	if !ok {
		return nil, fmt.Errorf("unexpected NFInstancesStoreAPI type %T", client.NFInstancesStoreAPI)
	}
	result, res, err := StoreApiSearchNFInstances(service, param)
	if res != nil && res.StatusCode == http.StatusTemporaryRedirect {
		err = fmt.Errorf("temporary redirect for non NRF consumer")
	}
	if res != nil && res.Body != nil {
		defer func() {
			if bodyCloseErr := res.Body.Close(); bodyCloseErr != nil {
				logger.ConsumerLog.Errorf("SearchNFInstances response body cannot close: %+v", bodyCloseErr)
			}
		}()
	}
	if err != nil {
		return result, err
	}
	if result == nil {
		return nil, fmt.Errorf("SearchNFInstances returned no result")
	}

	pcfSelf := pcfContext.PCF_Self()
	var nrfSubData *models.SubscriptionData
	var problemDetails *models.ProblemDetails
	var subscriptionErr error
	for _, nfProfile := range result.NfInstances {
		// checking whether the PCF subscribed to this target nfinstanceid or not
		if _, ok := pcfSelf.NfStatusSubscriptions.Load(nfProfile.NfInstanceId); !ok {
			nfInstanceIdCond := models.NewNfInstanceIdCond()
			nfInstanceIdCond.SetNfInstanceId(nfProfile.GetNfInstanceId())
			nrfSubscriptionData := models.SubscriptionData{
				NfStatusNotificationUri: fmt.Sprintf("%s/npcf-callback/v1/nf-status-notify", pcfSelf.GetIPv4Uri()),
				SubscrCond:              &models.SubscrCond{NfInstanceIdCond: nfInstanceIdCond},
				ReqNfType:               &requestNfType,
			}
			nrfSubData, problemDetails, err = CreateSubscription(nrfUri, nrfSubscriptionData)
			if problemDetails != nil {
				logger.ConsumerLog.Errorf("SendCreateSubscription to NRF, Problem[%+v]", problemDetails)
				if subscriptionErr == nil {
					cause := problemDetails.GetCause()
					if cause == "" {
						cause = "unknown problem"
					}
					subscriptionErr = fmt.Errorf("SendCreateSubscription to NRF failed: %s", cause)
				}
			} else if err != nil {
				logger.ConsumerLog.Errorf("SendCreateSubscription Error[%+v]", err)
				if subscriptionErr == nil {
					subscriptionErr = err
				}
			} else if nrfSubData != nil {
				pcfSelf.NfStatusSubscriptions.Store(nfProfile.GetNfInstanceId(), nrfSubData.GetSubscriptionId())
			}
		}
	}

	return result, subscriptionErr
}

func SendNFInstancesUDR(nrfUri, id string) string {
	targetNfType := models.NFTYPE_UDR
	requestNfType := models.NFTYPE_PCF
	configure := SearchNFInstancesRequestConfigurer(nil)
	// switch types {
	// case NFDiscoveryToUDRParamSupi:
	// 	localVarOptionals.Supi = optional.NewString(id)
	// case NFDiscoveryToUDRParamExtGroupId:
	// 	localVarOptionals.ExternalGroupIdentity = optional.NewString(id)
	// case NFDiscoveryToUDRParamGpsi:
	// 	localVarOptionals.Gpsi = optional.NewString(id)
	// }

	result, err := SendSearchNFInstances(nrfUri, targetNfType, requestNfType, configure)
	if err != nil {
		logger.Consumerlog.Error(err.Error())
		return ""
	}
	for _, profile := range result.NfInstances {
		if uri := util.SearchNFServiceUri(profile, models.SERVICENAME_NUDR_DR, models.NFSERVICESTATUS_REGISTERED); uri != "" {
			return uri
		}
	}
	return ""
}

func SendNFInstancesAMF(nrfUri string, guami models.Guami, serviceName models.ServiceName) string {
	targetNfType := models.NFTYPE_AMF
	requestNfType := models.NFTYPE_PCF

	configure := func(request Nnrf_NFDiscovery.ApiSearchNFInstancesRequest) Nnrf_NFDiscovery.ApiSearchNFInstancesRequest {
		return request.Guami(guami)
	}
	// switch types {
	// case NFDiscoveryToUDRParamSupi:
	// 	localVarOptionals.Supi = optional.NewString(id)
	// case NFDiscoveryToUDRParamExtGroupId:
	// 	localVarOptionals.ExternalGroupIdentity = optional.NewString(id)
	// case NFDiscoveryToUDRParamGpsi:
	// 	localVarOptionals.Gpsi = optional.NewString(id)
	// }

	result, err := SendSearchNFInstances(nrfUri, targetNfType, requestNfType, configure)
	if err != nil {
		logger.Consumerlog.Error(err.Error())
		return ""
	}
	for _, profile := range result.NfInstances {
		return util.SearchNFServiceUri(profile, serviceName, models.NFSERVICESTATUS_REGISTERED)
	}
	return ""
}

var DiscoverUdr = func() {
	self := pcfContext.PCF_Self()
	configure := func(request Nnrf_NFDiscovery.ApiSearchNFInstancesRequest) Nnrf_NFDiscovery.ApiSearchNFInstancesRequest {
		return request.ServiceNames([]models.ServiceName{models.SERVICENAME_NUDR_DR})
	}

	if resp, err := SendSearchNFInstances(self.NrfUri, models.NFTYPE_UDR, models.NFTYPE_PCF, configure); err != nil {
		logger.ConsumerLog.Errorln(err)
	} else {
		for _, nfProfile := range resp.NfInstances {
			udruri := util.SearchNFServiceUri(nfProfile, models.SERVICENAME_NUDR_DR, models.NFSERVICESTATUS_REGISTERED)
			if udruri != "" {
				self.SetDefaultUdrURI(udruri)
				break
			}
		}
	}
}
