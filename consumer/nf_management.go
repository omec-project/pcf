// SPDX-FileCopyrightText: 2025 Canonical Ltd.
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
// SPDX-License-Identifier: Apache-2.0
//

package consumer

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/Nnrf_NFManagement"
	"github.com/omec-project/openapi/v2/models"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/logger"
)

type NfProfileDynamicConfig struct {
	Plmns map[models.PlmnId]struct{}
	Dnns  map[string]struct{}
}

func getNfProfile(pcfContext *pcfContext.PCFContext, nfProfileDynamicConfig NfProfileDynamicConfig) (profile models.NFProfile, err error) {
	if pcfContext == nil {
		return profile, fmt.Errorf("pcf context has not been initialized. NF profile cannot be built")
	}
	profile.NfInstanceId = pcfContext.NfId
	profile.NfType = models.NFTYPE_PCF
	profile.NfStatus = models.NFSTATUS_REGISTERED
	profile.Ipv4Addresses = append(profile.Ipv4Addresses, pcfContext.RegisterIPv4)
	service := []models.NFService{}
	for _, nfService := range pcfContext.NfService {
		service = append(service, nfService)
	}
	profile.NfServices = service

	if len(nfProfileDynamicConfig.Plmns) > 0 {
		plmnCopy := make([]models.PlmnId, 0, len(nfProfileDynamicConfig.Plmns))
		for plmn := range nfProfileDynamicConfig.Plmns {
			plmnCopy = append(plmnCopy, plmn)
		}
		profile.PlmnList = plmnCopy
	}

	var dnnList []string
	if len(nfProfileDynamicConfig.Dnns) == 0 {
		logger.ConsumerLog.Warnln("DNN list has not been configured")
	} else {
		dnnList = make([]string, 0, len(nfProfileDynamicConfig.Dnns))
		for dnn := range nfProfileDynamicConfig.Dnns {
			dnnList = append(dnnList, dnn)
		}
	}

	profile.PcfInfo = &models.PcfInfo{
		DnnList: dnnList,
		// SupiRanges: &[]models.SupiRange{
		// 	{
		// 		//from TS 29.510 6.1.6.2.9 example2
		//		//no need to set SUPI range at this moment 2019/10/4
		// 		Start:   "123456789040000",
		// 		End:     "123456789059999",
		// 		Pattern: "^imsi-12345678904[0-9]{4}$",
		// 	},
		// },
	}
	return profile, err
}

var SendRegisterNFInstance = func(nfProfileDynamicConfig NfProfileDynamicConfig) (prof *models.NFProfile, resourceNrfUri string, err error) {
	self := pcfContext.PCF_Self()
	nfProfile, err := getNfProfile(self, nfProfileDynamicConfig)
	if err != nil {
		return &models.NFProfile{}, "", err
	}

	configuration := Nnrf_NFManagement.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = self.NrfUri
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	client := Nnrf_NFManagement.NewAPIClient(configuration)
	apiRegisterNFInstanceRequest := client.NFInstanceIDDocumentAPI.RegisterNFInstance(context.TODO(), nfProfile.GetNfInstanceId())
	apiRegisterNFInstanceRequest = apiRegisterNFInstanceRequest.NFProfile(nfProfile)
	receivedNfProfile, res, err := client.NFInstanceIDDocumentAPI.RegisterNFInstanceExecute(apiRegisterNFInstanceRequest)
	if err != nil {
		return &models.NFProfile{}, "", err
	}
	if res == nil {
		return &models.NFProfile{}, "", fmt.Errorf("no response from server")
	}
	defer func() {
		if res.Body != nil {
			if closeErr := res.Body.Close(); closeErr != nil {
				logger.ConsumerLog.Errorf("RegisterNFInstance response body cannot close: %+v", closeErr)
			}
		}
	}()

	switch res.StatusCode {
	case http.StatusOK: // NFUpdate
		logger.ConsumerLog.Debugln("PCF NF profile updated with complete replacement")
		return receivedNfProfile, "", nil
	case http.StatusCreated: // NFRegister
		resourceUri := res.Header.Get("Location")
		resourceNrfUri = resourceUri[:strings.Index(resourceUri, "/nnrf-nfm/")]
		retrieveNfInstanceId := resourceUri[strings.LastIndex(resourceUri, "/")+1:]
		self.NfId = retrieveNfInstanceId
		logger.ConsumerLog.Debugln("PCF NF profile registered to the NRF")
		return receivedNfProfile, resourceNrfUri, nil
	default:
		return receivedNfProfile, "", fmt.Errorf("unexpected status code returned by the NRF %d", res.StatusCode)
	}
}

var SendDeregisterNFInstance = func() error {
	logger.ConsumerLog.Infoln("send Deregister NFInstance")

	pcfSelf := pcfContext.PCF_Self()
	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = pcfSelf.NrfUri
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	apiDeregisterNFInstanceRequest := client.NFInstanceIDDocumentAPI.DeregisterNFInstance(context.Background(), pcfSelf.NfId)
	res, err := client.NFInstanceIDDocumentAPI.DeregisterNFInstanceExecute(apiDeregisterNFInstanceRequest)
	if err != nil {
		return err
	}
	if res == nil {
		return openapi.ReportError("server no response")
	}
	defer func() {
		if res.Body != nil {
			if closeErr := res.Body.Close(); closeErr != nil {
				logger.ConsumerLog.Errorf("DeregisterNFInstance response body cannot close: %+v", closeErr)
			}
		}
	}()
	if res.StatusCode == http.StatusNoContent {
		return nil
	}
	return openapi.ReportError("unexpected response code %d", res.StatusCode)
}

var SendUpdateNFInstance = func(patchItem []models.PatchItem) (nfProfile *models.NFProfile, problemDetails *models.ProblemDetails, err error) {
	logger.Consumerlog.Debugln("send Update NFInstance")

	pcfSelf := pcfContext.PCF_Self()
	configuration := Nnrf_NFManagement.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = pcfSelf.NrfUri
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	var res *http.Response
	apiUpdateNFInstanceRequest := client.NFInstanceIDDocumentAPI.UpdateNFInstance(context.Background(), pcfSelf.NfId)
	apiUpdateNFInstanceRequest = apiUpdateNFInstanceRequest.PatchItem(patchItem)
	nfProfile, res, err = client.NFInstanceIDDocumentAPI.UpdateNFInstanceExecute(apiUpdateNFInstanceRequest)
	if res != nil {
		defer func() {
			if res.Body != nil {
				if resCloseErr := res.Body.Close(); resCloseErr != nil {
					logger.Consumerlog.Errorf("UpdateNFInstance response cannot close: %+v", resCloseErr)
				}
			}
		}()
	}

	if err == nil {
		return nfProfile, nil, nil
	}

	if res != nil {
		if res.Status != err.Error() {
			logger.Consumerlog.Errorf("UpdateNFInstance received error response: %v", res.Status)
			return nil, nil, err
		}

		// Safe type assertion with error handling
		if genericErr, ok := err.(openapi.GenericOpenAPIError); ok {
			if model := genericErr.Model(); model != nil {
				if problem, ok := model.(models.ProblemDetails); ok {
					return nil, &problem, err
				}
			}
		}
		return nil, nil, err
	}

	// Server no response case
	err = openapi.ReportError("server no response")
	return nil, nil, err
}

func SendCreateSubscription(nrfUri string, nrfSubscriptionData models.SubscriptionData) (nrfSubData *models.SubscriptionData, problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Debugln("send Create Subscription")

	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = nrfUri
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	var res *http.Response
	apiCreateSubscriptionRequest := client.SubscriptionsCollectionAPI.CreateSubscription(context.TODO())
	apiCreateSubscriptionRequest = apiCreateSubscriptionRequest.SubscriptionData(nrfSubscriptionData)
	nrfSubData, res, err = client.SubscriptionsCollectionAPI.CreateSubscriptionExecute(apiCreateSubscriptionRequest)
	if res != nil {
		defer func() {
			if res.Body != nil {
				if resCloseErr := res.Body.Close(); resCloseErr != nil {
					logger.ConsumerLog.Errorf("SendCreateSubscription response cannot close: %+v", resCloseErr)
				}
			}
		}()
	}

	if err == nil {
		return nrfSubData, nil, nil
	}

	if res != nil {
		if res.Status != err.Error() {
			logger.ConsumerLog.Errorf("SendCreateSubscription received error response: %v", res.Status)
			return nil, nil, err
		}

		// Safe type assertion with error handling
		if genericErr, ok := err.(openapi.GenericOpenAPIError); ok {
			if model := genericErr.Model(); model != nil {
				if problem, ok := model.(models.ProblemDetails); ok {
					return nil, &problem, err
				}
			}
		}
		return nil, nil, err
	}

	// Server no response case
	err = openapi.ReportError("server no response")
	return nil, nil, err
}

func SendRemoveSubscription(subscriptionId string) (problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Infoln("send Remove Subscription")

	pcfSelf := pcfContext.PCF_Self()
	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = pcfSelf.NrfUri
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	client := Nnrf_NFManagement.NewAPIClient(configuration)
	var res *http.Response

	apiRemoveSubscriptionRequest := client.SubscriptionIDDocumentAPI.RemoveSubscription(context.Background(), subscriptionId)
	res, err = client.SubscriptionIDDocumentAPI.RemoveSubscriptionExecute(apiRemoveSubscriptionRequest)
	if res != nil {
		defer func() {
			if res.Body != nil {
				if bodyCloseErr := res.Body.Close(); bodyCloseErr != nil {
					logger.ConsumerLog.Errorf("RemoveSubscription response body cannot close: %+v", bodyCloseErr)
				}
			}
		}()
	}

	if err == nil {
		return nil, nil
	}

	if res != nil {
		if res.Status != err.Error() {
			return nil, err
		}

		// Safe type assertion with error handling
		if genericErr, ok := err.(openapi.GenericOpenAPIError); ok {
			if model := genericErr.Model(); model != nil {
				if problem, ok := model.(models.ProblemDetails); ok {
					return &problem, err
				}
			}
		}
		return nil, err
	}

	// Server no response case
	err = openapi.ReportError("server no response")
	return nil, err
}
