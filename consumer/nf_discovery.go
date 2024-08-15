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

	"github.com/antihax/optional"
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
	StoreApiSearchNFInstances = (*Nnrf_NFDiscovery.NFInstancesStoreApiService).SearchNFInstances
)

var SendSearchNFInstances = func(nrfUri string, targetNfType, requestNfType models.NfType, param *Nnrf_NFDiscovery.SearchNFInstancesParamOpts) (
	models.SearchResult, error,
) {
	if pcfContext.PCF_Self().EnableNrfCaching {
		return NRFCacheSearchNFInstances(nrfUri, targetNfType, requestNfType, param)
	} else {
		return SendNfDiscoveryToNrf(nrfUri, targetNfType, requestNfType, param)
	}
}

var SendNfDiscoveryToNrf = func(nrfUri string, targetNfType, requesterNfType models.NfType, param *Nnrf_NFDiscovery.SearchNFInstancesParamOpts,
) (models.SearchResult, error) {
	// Set client and set url
	configuration := Nnrf_NFDiscovery.NewConfiguration()
	configuration.SetBasePath(nrfUri)
	client := Nnrf_NFDiscovery.NewAPIClient(configuration)
	result, res, err := StoreApiSearchNFInstances(client.NFInstancesStoreApi, context.TODO(), targetNfType, requesterNfType, param)
	if res != nil && res.StatusCode == http.StatusTemporaryRedirect {
		err = fmt.Errorf("temporary redirect for non NRF consumer")
	}
	defer func() {
		if bodyCloseErr := res.Body.Close(); bodyCloseErr != nil {
			err = fmt.Errorf("SearchNFInstances' response body cannot close: %w", bodyCloseErr)
		}
	}()

	pcfSelf := pcfContext.PCF_Self()
	var nrfSubData models.NrfSubscriptionData
	var problemDetails *models.ProblemDetails
	for _, nfProfile := range result.NfInstances {
		// checking whether the PCF subscribed to this target nfinstanceid or not
		if _, ok := pcfSelf.NfStatusSubscriptions.Load(nfProfile.NfInstanceId); !ok {
			nrfSubscriptionData := models.NrfSubscriptionData{
				NfStatusNotificationUri: fmt.Sprintf("%s/npcf-callback/v1/nf-status-notify", pcfSelf.GetIPv4Uri()),
				SubscrCond:              &models.NfInstanceIdCond{NfInstanceId: nfProfile.NfInstanceId},
				ReqNfType:               requesterNfType,
			}
			nrfSubData, problemDetails, err = CreateSubscription(nrfUri, nrfSubscriptionData)
			if problemDetails != nil {
				logger.ConsumerLog.Errorf("SendCreateSubscription to NRF, Problem[%+v]", problemDetails)
			} else if err != nil {
				logger.ConsumerLog.Errorf("SendCreateSubscription Error[%+v]", err)
			}
			pcfSelf.NfStatusSubscriptions.Store(nfProfile.NfInstanceId, nrfSubData.SubscriptionId)
		}
	}

	return result, err
}

func SendNFInstancesUDR(nrfUri, id string) string {
	targetNfType := models.NfType_UDR
	requestNfType := models.NfType_PCF
	localVarOptionals := &Nnrf_NFDiscovery.SearchNFInstancesParamOpts{
		// 	DataSet: optional.NewInterface(models.DataSetId_SUBSCRIPTION),
	}
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
		if uri := util.SearchNFServiceUri(profile, models.ServiceName_NUDR_DR, models.NfServiceStatus_REGISTERED); uri != "" {
			return uri
		}
	}
	return ""
}

func SendNFInstancesAMF(nrfUri string, guami models.Guami, serviceName models.ServiceName) string {
	targetNfType := models.NfType_AMF
	requestNfType := models.NfType_PCF

	localVarOptionals := &Nnrf_NFDiscovery.SearchNFInstancesParamOpts{
		Guami: optional.NewInterface(util.MarshToJsonString(guami)),
	}
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
		return util.SearchNFServiceUri(profile, serviceName, models.NfServiceStatus_REGISTERED)
	}
	return ""
}
