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

	"github.com/omec-project/openapi"
	"github.com/omec-project/openapi/Nnrf_NFManagement"
	"github.com/omec-project/openapi/models"
	pcfContext "github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/logger"
)

type NfProfileDynamicConfig struct {
	Plmns map[models.PlmnId]struct{}
	Dnns  map[string]struct{}
}

func getNfProfile(pcfContext *pcfContext.PCFContext, nfProfileDynamicConfig NfProfileDynamicConfig) (profile models.NfProfile, err error) {
	if pcfContext == nil {
		return profile, fmt.Errorf("pcf context has not been intialized. NF profile cannot be built")
	}
	profile.NfInstanceId = pcfContext.NfId
	profile.NfType = models.NfType_PCF
	profile.NfStatus = models.NfStatus_REGISTERED
	profile.Ipv4Addresses = append(profile.Ipv4Addresses, pcfContext.RegisterIPv4)
	service := []models.NfService{}
	for _, nfService := range pcfContext.NfService {
		service = append(service, nfService)
	}
	profile.NfServices = &service

	if len(nfProfileDynamicConfig.Plmns) > 0 {
		plmnCopy := make([]models.PlmnId, len(nfProfileDynamicConfig.Plmns))
		for plmn := range nfProfileDynamicConfig.Plmns {
			plmnCopy = append(plmnCopy, plmn)
		}
		profile.PlmnList = &plmnCopy
	}

	var dnnList []string
	if len(nfProfileDynamicConfig.Dnns) == 0 {
		logger.ConsumerLog.Warnln("DNN list has not been configured")
	} else {
		dnnList = make([]string, len(nfProfileDynamicConfig.Dnns))
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

var SendRegisterNFInstance = func(nfProfileDynamicConfig NfProfileDynamicConfig) (prof models.NfProfile, resourceNrfUri string, err error) {
	self := pcfContext.PCF_Self()
	nfProfile, err := getNfProfile(self, nfProfileDynamicConfig)
	if err != nil {
		return models.NfProfile{}, "", err
	}

	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(self.NrfUri)
	client := Nnrf_NFManagement.NewAPIClient(configuration)
	receivedNfProfile, res, err := client.NFInstanceIDDocumentApi.RegisterNFInstance(context.TODO(), nfProfile.NfInstanceId, nfProfile)
	logger.ConsumerLog.Debugf("RegisterNFInstance done using profile: %+v", nfProfile)

	if err != nil {
		return models.NfProfile{}, "", err
	}
	if res == nil {
		return models.NfProfile{}, "", fmt.Errorf("no response from server")
	}

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
	configuration.SetBasePath(pcfSelf.NrfUri)
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	res, err := client.NFInstanceIDDocumentApi.DeregisterNFInstance(context.Background(), pcfSelf.NfId)
	if err != nil {
		return err
	}
	if res == nil {
		return fmt.Errorf("no response from server")
	}
	if res.StatusCode == 204 {
		return nil
	}
	return fmt.Errorf("unexpected response code")
}

var SendUpdateNFInstance = func(patchItem []models.PatchItem) (receivedNfProfile models.NfProfile, problemDetails *models.ProblemDetails, err error) {
	logger.Consumerlog.Debugln("send Update NFInstance")

	pcfSelf := pcfContext.PCF_Self()
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(pcfSelf.NrfUri)
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	receivedNfProfile, res, err := client.NFInstanceIDDocumentApi.UpdateNFInstance(context.Background(), pcfSelf.NfId, patchItem)
	if err == nil {
		return
	} else if res != nil {
		defer func() {
			if resCloseErr := res.Body.Close(); resCloseErr != nil {
				logger.Consumerlog.Errorf("UpdateNFInstance response cannot close: %+v", resCloseErr)
			}
		}()
		if res.Status != err.Error() {
			logger.Consumerlog.Errorf("UpdateNFInstance received error response: %v", res.Status)
			return
		}
		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = fmt.Errorf("server no response")
	}
	return
}

func SendCreateSubscription(nrfUri string, nrfSubscriptionData models.NrfSubscriptionData) (nrfSubData models.NrfSubscriptionData, problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Debugln("send Create Subscription")

	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(nrfUri)
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	var res *http.Response
	nrfSubData, res, err = client.SubscriptionsCollectionApi.CreateSubscription(context.TODO(), nrfSubscriptionData)
	if err == nil {
		return
	} else if res != nil {
		defer func() {
			if resCloseErr := res.Body.Close(); resCloseErr != nil {
				logger.ConsumerLog.Errorf("SendCreateSubscription response cannot close: %+v", resCloseErr)
			}
		}()
		if res.Status != err.Error() {
			logger.ConsumerLog.Errorf("SendCreateSubscription received error response: %v", res.Status)
			return
		}
		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = fmt.Errorf("server no response")
	}
	return
}

func SendRemoveSubscription(subscriptionId string) (problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Infoln("send Remove Subscription")

	pcfSelf := pcfContext.PCF_Self()
	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(pcfSelf.NrfUri)
	client := Nnrf_NFManagement.NewAPIClient(configuration)
	var res *http.Response

	res, err = client.SubscriptionIDDocumentApi.RemoveSubscription(context.Background(), subscriptionId)
	if err == nil {
		return
	} else if res != nil {
		defer func() {
			if bodyCloseErr := res.Body.Close(); bodyCloseErr != nil {
				err = fmt.Errorf("RemoveSubscription's response body cannot close: %w", bodyCloseErr)
			}
		}()
		if res.Status != err.Error() {
			return
		}
		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = fmt.Errorf("server no response")
	}
	return
}
