// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// SPDX-License-Identifier: Apache-2.0
/*
 * PCF Unit Testcases
 *
 */

package pcftests

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	protos "github.com/omec-project/config5g/proto/sdcoreConfig"
	"github.com/omec-project/openapi/Nnrf_NFDiscovery"
	"github.com/omec-project/openapi/models"
	"github.com/omec-project/pcf/consumer"
	"github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/factory"
	"github.com/omec-project/pcf/service"
	"github.com/stretchr/testify/assert"
)

var (
	PCFTest       = &service.PCF{}
	bitRateValues = make(map[int64]string)
)

func init() {
	bitRateValues = map[int64]string{
		1000:        "1 Kbps",
		67200:       "67 Kbps",
		777111:      "777 Kbps",
		77711000:    "77 Mbps",
		64435000:    "64435 Kbps",
		77711000000: "77 Gbps",
		64435000111: "64435 Mbps",
	}
	if err := factory.InitConfigFactory("../pcftests/pcfcfg.yaml"); err != nil {
		fmt.Printf("Could not InitConfigFactory: %+v\n", err)
	}
}

func TestUpdatePcfSubscriberPolicyDataAdd(t *testing.T) {
	var nrp protos.NetworkSliceResponse
	err := json.Unmarshal(Data, &nrp)
	if err != nil {
		panic(err)
	}
	for _, ns := range nrp.NetworkSlice {
		PCFTest.UpdatePcfSubsriberPolicyData(ns)
	}
	self := context.PCF_Self()
	assert.Equal(t, len(self.PcfSubscriberPolicyData), 3)
}

func TestCheckNRFCachingIsEnabled(t *testing.T) {
	got := factory.PcfConfig.Configuration.EnableNrfCaching
	assert.Equal(t, got, true, "NRF Caching is not enabled.")
}

func TestUpdatePcfSubscriberPolicyDataUpdate(t *testing.T) {
	var nrp protos.NetworkSliceResponse
	err := json.Unmarshal(UData, &nrp)
	if err != nil {
		panic(err)
	}
	for _, ns := range nrp.NetworkSlice {
		PCFTest.UpdatePcfSubsriberPolicyData(ns)
	}
	self := context.PCF_Self()
	assert.Equal(t, len(self.PcfSubscriberPolicyData), 5)
}

// Two imsis deleted and 1 imsi added in device group
func TestUpdatePcfSubscriberPolicyDataUpdate1(t *testing.T) {
	var nrp protos.NetworkSliceResponse
	err := json.Unmarshal(UData1, &nrp)
	if err != nil {
		panic(err)
	}
	for _, ns := range nrp.NetworkSlice {
		PCFTest.UpdatePcfSubsriberPolicyData(ns)
	}
	self := context.PCF_Self()
	assert.Equal(t, len(self.PcfSubscriberPolicyData), 4)
}

func TestUpdatePcfSubscriberPolicyDataDel(t *testing.T) {
	var nrp protos.NetworkSliceResponse
	err := json.Unmarshal(DelData, &nrp)
	if err != nil {
		panic(err)
	}
	for _, ns := range nrp.NetworkSlice {
		PCFTest.UpdatePcfSubsriberPolicyData(ns)
	}
	self := context.PCF_Self()
	assert.Equal(t, len(self.PcfSubscriberPolicyData), 0)
}

func TestUpdatePolicyForAllIMSIs(t *testing.T) {
	var nrp protos.NetworkSliceResponse
	err := json.Unmarshal(Data, &nrp)
	if err != nil {
		panic(err)
	}
	Rsp := make(chan *protos.NetworkSliceResponse)
	go func() {
		Rsp <- &nrp
	}()
	go func() {
		PCFTest.UpdateConfig(Rsp)
	}()
	time.Sleep(2 * time.Second)
	self := context.PCF_Self()
	authSessAmbr := "AuthSessAmbr: Uplink: 100 Kbps, Downlink: 50 Kbps"
	policyimsi1, exist1 := self.PcfSubscriberPolicyData["123456789123456"]
	policyimsi2, exist2 := self.PcfSubscriberPolicyData["123456789123457"]
	policyimsi3, exist3 := self.PcfSubscriberPolicyData["123456789123458"]
	assert.EqualValues(
		t,
		strings.Contains(policyimsi1.String(), authSessAmbr),
		strings.Contains(policyimsi2.String(), authSessAmbr),
		strings.Contains(policyimsi3.String(), authSessAmbr),
		true,
	)
	assert.EqualValues(t, exist1, exist2, exist3, true)

	// Update Slice Info with different AMBR Values: Uplink: 20 Kbps, Downlink: 80 Kbps.
	// Two more IMSIs are added.
	err = json.Unmarshal(UData, &nrp)
	if err != nil {
		panic(err)
	}
	Rsp = make(chan *protos.NetworkSliceResponse)
	go func() {
		Rsp <- &nrp
	}()
	go func() {
		PCFTest.UpdateConfig(Rsp)
	}()
	time.Sleep(2 * time.Second)
	self = context.PCF_Self()
	authSessAmbr = "AuthSessAmbr: Uplink: 20 Kbps, Downlink: 80 Kbps"
	policyimsi1, exist1 = self.PcfSubscriberPolicyData["123456789123456"]
	policyimsi2, exist2 = self.PcfSubscriberPolicyData["123456789123457"]
	policyimsi3, exist3 = self.PcfSubscriberPolicyData["123456789123458"]
	policyimsi4, exist4 := self.PcfSubscriberPolicyData["123456789123459"]
	policyimsi5, exist5 := self.PcfSubscriberPolicyData["123456789123460"]
	assert.EqualValues(
		t,
		strings.Contains(policyimsi1.String(), authSessAmbr),
		strings.Contains(policyimsi2.String(), authSessAmbr),
		strings.Contains(policyimsi3.String(), authSessAmbr),
		strings.Contains(policyimsi4.String(), authSessAmbr),
		strings.Contains(policyimsi5.String(), authSessAmbr),
		true,
	)
	assert.EqualValues(t, exist1, exist2, exist3, exist4, exist5, true)

	// Update Slice Info with different AMBR Values: Uplink: 100 Kbps, Downlink: 50 Kbps.
	// Two IMSIs are deleted, one IMSI added.
	err = json.Unmarshal(UData1, &nrp)
	if err != nil {
		panic(err)
	}
	Rsp = make(chan *protos.NetworkSliceResponse)
	go func() {
		Rsp <- &nrp
	}()
	go func() {
		PCFTest.UpdateConfig(Rsp)
	}()
	time.Sleep(2 * time.Second)
	self = context.PCF_Self()
	authSessAmbr = "AuthSessAmbr: Uplink: 100 Kbps, Downlink: 50 Kbps"
	policyimsi1, exist1 = self.PcfSubscriberPolicyData["123456789123456"]
	policyimsi2, exist2 = self.PcfSubscriberPolicyData["123456789123459"]
	policyimsi3, exist3 = self.PcfSubscriberPolicyData["123456789123460"]
	policyimsi4, exist4 = self.PcfSubscriberPolicyData["123456789123461"]
	assert.EqualValues(
		t,
		strings.Contains(policyimsi1.String(), authSessAmbr),
		strings.Contains(policyimsi2.String(), authSessAmbr),
		strings.Contains(policyimsi3.String(), authSessAmbr),
		strings.Contains(policyimsi4.String(), authSessAmbr),
		true,
	)
	assert.EqualValues(t, exist1, exist2, exist3, exist4, true)

	// Checking policy for removed IMSIs
	_, exist5 = self.PcfSubscriberPolicyData["123456789123457"]
	_, exist6 := self.PcfSubscriberPolicyData["123456789123458"]
	assert.EqualValues(t, exist5, exist6, false)
}

func TestGetBitRateUnit(t *testing.T) {
	fmt.Printf("test case TestGetBitRateUnit \n")
	for value, expVal := range bitRateValues {
		val, unit := service.GetBitRateUnit(value)
		assert.Equal(t, strconv.FormatInt(val, 10)+unit, expVal)
	}
}

func TestRegisterNF(t *testing.T) {
	// Save current function and restore at the end:
	origRegisterNFInstance := consumer.SendRegisterNFInstance
	origSearchNFInstances := consumer.SendSearchNFInstances
	origUpdateNFInstance := consumer.SendUpdateNFInstance
	defer func() {
		consumer.SendRegisterNFInstance = origRegisterNFInstance
		consumer.SendSearchNFInstances = origSearchNFInstances
		consumer.SendUpdateNFInstance = origUpdateNFInstance
	}()
	fmt.Printf("test case TestRegisterNF \n")
	var prof models.NfProfile
	consumer.SendRegisterNFInstance = func(nrfUri string, nfInstanceId string, profile models.NfProfile) (models.NfProfile, string, string, error) {
		prof = profile
		prof.HeartBeatTimer = 1
		fmt.Printf("Test RegisterNFInstance called\n")
		return prof, "", "", nil
	}
	consumer.SendSearchNFInstances = func(nrfUri string, targetNfType, requestNfType models.NfType, param *Nnrf_NFDiscovery.SearchNFInstancesParamOpts) (models.SearchResult, error) {
		fmt.Printf("Test SearchNFInstance called\n")
		return models.SearchResult{}, nil
	}
	consumer.SendUpdateNFInstance = func(patchItem []models.PatchItem) (nfProfile models.NfProfile, problemDetails *models.ProblemDetails, err error) {
		return prof, nil, nil
	}
	go PCFTest.RegisterNF()
	service.ConfigPodTrigger <- true
	time.Sleep(5 * time.Second)
	assert.Equal(t, service.KeepAliveTimer != nil, true)

	service.ConfigPodTrigger <- false
	time.Sleep(1 * time.Second)
	assert.Equal(t, service.KeepAliveTimer == nil, true)
}

func TestDiscoverUDR(t *testing.T) {
	fmt.Printf("test case DiscoverUDR \n")
	callCountSearchNFInstances := 0
	callCountSendNfDiscovery := 0
	consumer.NRFCacheSearchNFInstances = func(nrfUri string, targetNfType, requestNfType models.NfType, param *Nnrf_NFDiscovery.SearchNFInstancesParamOpts) (models.SearchResult, error) {
		fmt.Printf("Test SearchNFInstance called\n")
		callCountSearchNFInstances++
		return models.SearchResult{}, nil
	}
	consumer.SendNfDiscoveryToNrf = func(nrfUri string, targetNfType, requestNfType models.NfType, param *Nnrf_NFDiscovery.SearchNFInstancesParamOpts) (models.SearchResult, error) {
		fmt.Printf("Test SendNfDiscoveryToNrf called\n")
		callCountSendNfDiscovery++
		return models.SearchResult{}, nil
	}
	// NRF caching enabled
	context.PCF_Self().EnableNrfCaching = true
	// Try to discover UDR first time when NRF caching enabled
	PCFTest.DiscoverUdr()
	assert.Equal(t, 1, callCountSearchNFInstances, "NF instance should be searched in the cache.")
	assert.Equal(t, 0, callCountSendNfDiscovery, "NF discovery request should not be sent to NRF.")
	// NRF caching disabled
	context.PCF_Self().EnableNrfCaching = false
	// Try to discover UDR second time when NRF caching disabled
	PCFTest.DiscoverUdr()
	assert.Equal(t, 1, callCountSearchNFInstances, "NF instance should be searched in the cache.")
	assert.Equal(t, 1, callCountSendNfDiscovery, "NF discovery request should not be sent to NRF.")
	context.PCF_Self().EnableNrfCaching = false
}
