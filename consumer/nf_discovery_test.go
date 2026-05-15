// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

package consumer

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/omec-project/openapi/v2/Nnrf_NFDiscovery"
	"github.com/omec-project/openapi/v2/models"
	pcfContext "github.com/omec-project/pcf/context"
)

func TestSendNfDiscoveryToNrf_DoesNotPanicOnNilResponse(t *testing.T) {
	originalStore := StoreApiSearchNFInstances
	defer func() { StoreApiSearchNFInstances = originalStore }()

	StoreApiSearchNFInstances = func(*Nnrf_NFDiscovery.NFInstancesStoreAPIService, Nnrf_NFDiscovery.ApiSearchNFInstancesRequest) (*models.SearchResult, *http.Response, error) {
		return nil, nil, errors.New("store search failed")
	}

	_, err := SendNfDiscoveryToNrf(context.Background(), "http://nrf", models.NFTYPE_UDR, models.NFTYPE_PCF, Nnrf_NFDiscovery.ApiSearchNFInstancesRequest{})
	if err == nil || err.Error() != "store search failed" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSendNfDiscoveryToNrf_DoesNotStoreSubscriptionOnCreateFailure(t *testing.T) {
	originalStore := StoreApiSearchNFInstances
	originalCreate := CreateSubscription
	defer func() {
		StoreApiSearchNFInstances = originalStore
		CreateSubscription = originalCreate
		pcfContext.PCF_Self().NfStatusSubscriptions.Delete("nf-instance")
	}()

	pcfContext.PCF_Self().NfStatusSubscriptions.Delete("nf-instance")
	StoreApiSearchNFInstances = func(*Nnrf_NFDiscovery.NFInstancesStoreAPIService, Nnrf_NFDiscovery.ApiSearchNFInstancesRequest) (*models.SearchResult, *http.Response, error) {
		return &models.SearchResult{NfInstances: []models.NFProfileDiscovery{{NfInstanceId: "nf-instance"}}}, nil, nil
	}
	CreateSubscription = func(string, models.SubscriptionData) (*models.SubscriptionData, *models.ProblemDetails, error) {
		return nil, nil, errors.New("create failed")
	}

	_, err := SendNfDiscoveryToNrf(context.Background(), "http://nrf", models.NFTYPE_UDR, models.NFTYPE_PCF, Nnrf_NFDiscovery.ApiSearchNFInstancesRequest{})
	if err == nil || err.Error() != "create failed" {
		t.Fatalf("unexpected error: %v", err)
	}
	if value, ok := pcfContext.PCF_Self().NfStatusSubscriptions.Load("nf-instance"); ok {
		t.Fatalf("expected no stored subscription, got %v", value)
	}
}

func TestSendNfDiscoveryToNrf_PropagatesSubscriptionProblemDetails(t *testing.T) {
	originalStore := StoreApiSearchNFInstances
	originalCreate := CreateSubscription
	defer func() {
		StoreApiSearchNFInstances = originalStore
		CreateSubscription = originalCreate
		pcfContext.PCF_Self().NfStatusSubscriptions.Delete("nf-instance")
	}()

	problem := models.NewProblemDetails()
	problem.SetCause("SERVER_ERROR")
	StoreApiSearchNFInstances = func(*Nnrf_NFDiscovery.NFInstancesStoreAPIService, Nnrf_NFDiscovery.ApiSearchNFInstancesRequest) (*models.SearchResult, *http.Response, error) {
		return &models.SearchResult{NfInstances: []models.NFProfileDiscovery{{NfInstanceId: "nf-instance"}}}, nil, nil
	}
	CreateSubscription = func(string, models.SubscriptionData) (*models.SubscriptionData, *models.ProblemDetails, error) {
		return nil, problem, nil
	}

	_, err := SendNfDiscoveryToNrf(context.Background(), "http://nrf", models.NFTYPE_UDR, models.NFTYPE_PCF, Nnrf_NFDiscovery.ApiSearchNFInstancesRequest{})
	if err == nil || err.Error() != "SendCreateSubscription to NRF failed: SERVER_ERROR" {
		t.Fatalf("unexpected error: %v", err)
	}
}
