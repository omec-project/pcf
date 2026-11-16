// Copyright (C) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2025 Canonical Ltd.
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"context"
	"fmt"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/nrfclient"
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
	profile = *models.NewNFProfileWithDefaults()
	profile.SetNfInstanceId(pcfContext.NfId)
	profile.SetNfType(models.NFTYPE_PCF)
	profile.SetNfStatus(models.NFSTATUS_REGISTERED)
	profile.SetIpv4Addresses(append(profile.GetIpv4Addresses(), pcfContext.RegisterIPv4))
	service := []models.NFService{}
	serviceList := map[string]models.NFService{}
	for _, nfService := range pcfContext.NfService {
		service = append(service, nfService)
		serviceList[nfService.GetServiceInstanceId()] = nfService
	}
	profile.SetNfServices(service)
	profile.SetNfServiceList(serviceList)

	if len(nfProfileDynamicConfig.Plmns) > 0 {
		plmnCopy := make([]models.PlmnId, 0, len(nfProfileDynamicConfig.Plmns))
		for plmn := range nfProfileDynamicConfig.Plmns {
			plmnCopy = append(plmnCopy, plmn)
		}
		profile.SetPlmnList(plmnCopy)
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

	pcfInfo := models.NewPcfInfo()
	pcfInfo.SetDnnList(dnnList)
	profile.SetPcfInfo(*pcfInfo)
	return profile, err
}

func newNrfClient(nrfUri string) *nrfclient.Client {
	return nrfclient.New(nrfUri, nrfclient.WithLogger(logger.ConsumerLog))
}

// SendRegisterNFInstance and SendDeregisterNFInstance take the context of the registration service, which holds
// its registration mutex while they run and cancels the context to end them when a new configuration arrives or
// the NF terminates.
var SendRegisterNFInstance = func(ctx context.Context, nfProfileDynamicConfig NfProfileDynamicConfig) (prof *models.NFProfile, resourceNrfUri string, err error) {
	self := pcfContext.PCF_Self()
	nfProfile, err := getNfProfile(self, nfProfileDynamicConfig)
	if err != nil {
		return models.NewNFProfileWithDefaults(), "", err
	}

	result, err := newNrfClient(self.NrfUri).Register(ctx, nfProfile)
	if err != nil {
		return models.NewNFProfileWithDefaults(), "", err
	}
	if result.Created {
		logger.ConsumerLog.Debugln("PCF NF profile registered to the NRF")
		if result.NfInstanceID != "" {
			self.NfId = result.NfInstanceID
		}
	} else {
		logger.ConsumerLog.Debugln("PCF NF profile updated with complete replacement")
	}
	return result.Profile, result.NrfURI, nil
}

var SendDeregisterNFInstance = func(ctx context.Context) error {
	logger.ConsumerLog.Infoln("send Deregister NFInstance")

	pcfSelf := pcfContext.PCF_Self()
	return newNrfClient(pcfSelf.NrfUri).Deregister(ctx, pcfSelf.NfId)
}

var SendUpdateNFInstance = func(ctx context.Context, patchItem []models.PatchItem) (nfProfile *models.NFProfile, problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Debugln("send Update NFInstance")

	pcfSelf := pcfContext.PCF_Self()
	return newNrfClient(pcfSelf.NrfUri).Update(ctx, pcfSelf.NfId, patchItem)
}

func SendCreateSubscription(nrfUri string, nrfSubscriptionData models.SubscriptionData) (nrfSubData *models.SubscriptionData, problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Debugln("send Create Subscription")

	return newNrfClient(nrfUri).CreateSubscription(context.TODO(), nrfSubscriptionData)
}

func SendRemoveSubscription(subscriptionId string) (problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Infoln("send Remove Subscription")

	pcfSelf := pcfContext.PCF_Self()
	return newNrfClient(pcfSelf.NrfUri).RemoveSubscription(context.Background(), subscriptionId)
}
