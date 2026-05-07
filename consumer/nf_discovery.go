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

	"github.com/omec-project/openapi/Nnrf_NFDiscovery"
	"github.com/omec-project/openapi/models"
	nrfCache "github.com/omec-project/openapi/nrfcache"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/logger"
	"github.com/omec-project/pcf/util"
)

var (
	CreateSubscription        = SendCreateSubscription
	NRFCacheSearchNFInstances = nrfCache.SearchNFInstances
	StoreApiSearchNFInstances = (*Nnrf_NFDiscovery.NFInstancesStoreAPIService).SearchNFInstancesExecute
)

var SendSearchNFInstances = func(nrfUri string, targetNfType, requestNfType models.NFType, param Nnrf_NFDiscovery.ApiSearchNFInstancesRequest) (
	*models.SearchResult, error,
) {
	ctx := context.Background()
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

	param = param.TargetNfType(targetNfType)
	param = param.RequesterNfType(requestNfType)
	result, res, err := StoreApiSearchNFInstances(client.NFInstancesStoreAPI.(*Nnrf_NFDiscovery.NFInstancesStoreAPIService), param)
	if res != nil && res.StatusCode == http.StatusTemporaryRedirect {
		err = fmt.Errorf("temporary redirect for non NRF consumer")
	}
	defer func() {
		if bodyCloseErr := res.Body.Close(); bodyCloseErr != nil {
			err = fmt.Errorf("SearchNFInstances' response body cannot close: %+w", bodyCloseErr)
		}
	}()

	pcfSelf := pcfContext.PCF_Self()
	var nrfSubData *models.SubscriptionData
	var problemDetails *models.ProblemDetails
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
			} else if err != nil {
				logger.ConsumerLog.Errorf("SendCreateSubscription Error[%+v]", err)
			}
			pcfSelf.NfStatusSubscriptions.Store(nfProfile.GetNfInstanceId(), nrfSubData.GetSubscriptionId())
		}
	}

	return result, err
}

func SendNFInstancesUDR(nrfUri, id string) string {
	targetNfType := models.NFTYPE_UDR
	requestNfType := models.NFTYPE_PCF
	localVarOptionals := Nnrf_NFDiscovery.ApiSearchNFInstancesRequest{}
	// switch types {
	// case NFDiscoveryToUDRParamSupi:
	// 	localVarOptionals.Supi = optional.NewString(id)
	// case NFDiscoveryToUDRParamExtGroupId:
	// 	localVarOptionals.ExternalGroupIdentity = optional.NewString(id)
	// case NFDiscoveryToUDRParamGpsi:
	// 	localVarOptionals.Gpsi = optional.NewString(id)
	// }

	result, err := SendSearchNFInstances(nrfUri, targetNfType, requestNfType, localVarOptionals)
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

	localVarOptionals := Nnrf_NFDiscovery.ApiSearchNFInstancesRequest{}
	localVarOptionals.Guami(guami)
	// switch types {
	// case NFDiscoveryToUDRParamSupi:
	// 	localVarOptionals.Supi = optional.NewString(id)
	// case NFDiscoveryToUDRParamExtGroupId:
	// 	localVarOptionals.ExternalGroupIdentity = optional.NewString(id)
	// case NFDiscoveryToUDRParamGpsi:
	// 	localVarOptionals.Gpsi = optional.NewString(id)
	// }

	result, err := SendSearchNFInstances(nrfUri, targetNfType, requestNfType, localVarOptionals)
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
	param := Nnrf_NFDiscovery.ApiSearchNFInstancesRequest{}
	param = param.ServiceNames([]models.ServiceName{models.SERVICENAME_NUDR_DR})

	if resp, err := SendSearchNFInstances(self.NrfUri, models.NFTYPE_UDR, models.NFTYPE_PCF, param); err != nil {
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
