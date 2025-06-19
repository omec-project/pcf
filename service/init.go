// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// SPDX-FileCopyrightText: 2024 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

package service

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/antihax/optional"
	"github.com/gin-contrib/cors"
	grpcClient "github.com/omec-project/config5g/proto/client"
	protos "github.com/omec-project/config5g/proto/sdcoreConfig"
	"github.com/omec-project/openapi/Nnrf_NFDiscovery"
	openapiLogger "github.com/omec-project/openapi/logger"
	"github.com/omec-project/openapi/models"
	nrfCache "github.com/omec-project/openapi/nrfcache"
	"github.com/omec-project/pcf/ampolicy"
	"github.com/omec-project/pcf/bdtpolicy"
	"github.com/omec-project/pcf/callback"
	"github.com/omec-project/pcf/consumer"
	"github.com/omec-project/pcf/context"
	"github.com/omec-project/pcf/factory"
	"github.com/omec-project/pcf/httpcallback"
	"github.com/omec-project/pcf/internal/notifyevent"
	"github.com/omec-project/pcf/logger"
	"github.com/omec-project/pcf/metrics"
	"github.com/omec-project/pcf/oam"
	"github.com/omec-project/pcf/policyauthorization"
	"github.com/omec-project/pcf/smpolicy"
	"github.com/omec-project/pcf/uepolicy"
	"github.com/omec-project/pcf/util"
	"github.com/omec-project/util/http2_util"
	"github.com/omec-project/util/idgenerator"
	utilLogger "github.com/omec-project/util/logger"
	"github.com/urfave/cli/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type PCF struct{}

type (
	// Config information.
	Config struct {
		cfg string
	}
)

var (
	ConfigPodTrigger    chan bool
	KeepAliveTimer      *time.Timer
	KeepAliveTimerMutex sync.Mutex
)

func init() {
	ConfigPodTrigger = make(chan bool)
}

var config Config

var pcfCLi = []cli.Flag{
	&cli.StringFlag{
		Name:     "cfg",
		Usage:    "pcf config file",
		Required: true,
	},
}

func (*PCF) GetCliCmd() (flags []cli.Flag) {
	return pcfCLi
}

func (pcf *PCF) Initialize(c *cli.Command) error {
	config = Config{
		cfg: c.String("cfg"),
	}

	absPath, err := filepath.Abs(config.cfg)
	if err != nil {
		logger.CfgLog.Errorln(err)
		return err
	}

	if err := factory.InitConfigFactory(absPath); err != nil {
		return err
	}

	pcf.setLogLevel()

	if err := factory.CheckConfigVersion(); err != nil {
		return err
	}

	factory.PcfConfig.CfgLocation = absPath

	if os.Getenv("MANAGED_BY_CONFIG_POD") == "true" {
		logger.InitLog.Infoln("MANAGED_BY_CONFIG_POD is true")
		go manageGrpcClient(factory.PcfConfig.Configuration.WebuiUri, pcf)
	} else {
		go func() {
			logger.InitLog.Infoln("use helm chart config")
			ConfigPodTrigger <- true
		}()
	}
	return nil
}

// manageGrpcClient connects the config pod GRPC server and subscribes the config changes.
// Then it updates PCF configuration.
func manageGrpcClient(webuiUri string, pcf *PCF) {
	var configChannel chan *protos.NetworkSliceResponse
	var client grpcClient.ConfClient
	var stream protos.ConfigService_NetworkSliceSubscribeClient
	var err error
	count := 0
	for {
		if client != nil {
			if client.CheckGrpcConnectivity() != "READY" {
				time.Sleep(time.Second * 30)
				count++
				if count > 5 {
					err = client.GetConfigClientConn().Close()
					if err != nil {
						logger.InitLog.Infof("failing ConfigClient is not closed properly: %+v", err)
					}
					client = nil
					count = 0
				}
				logger.InitLog.Infoln("checking the connectivity readiness")
				continue
			}

			if stream == nil {
				stream, err = client.SubscribeToConfigServer()
				if err != nil {
					logger.InitLog.Infof("failing SubscribeToConfigServer: %+v", err)
					continue
				}
			}

			if configChannel == nil {
				configChannel = client.PublishOnConfigChange(true, stream)
				logger.InitLog.Infoln("PublishOnConfigChange is triggered")
				go pcf.UpdateConfig(configChannel)
				logger.InitLog.Infoln("PCF updateConfig is triggered")
			}

			time.Sleep(time.Second * 5) // Fixes (avoids) 100% CPU utilization
		} else {
			client, err = grpcClient.ConnectToConfigServer(webuiUri)
			stream = nil
			configChannel = nil
			logger.InitLog.Infoln("connecting to config server")
			if err != nil {
				logger.InitLog.Errorf("%+v", err)
			}
			continue
		}
	}
}

func (pcf *PCF) setLogLevel() {
	if factory.PcfConfig.Logger == nil {
		logger.InitLog.Warnln("PCF config without log level setting")
		return
	}

	if factory.PcfConfig.Logger.PCF != nil {
		if factory.PcfConfig.Logger.PCF.DebugLevel != "" {
			if level, err := zapcore.ParseLevel(factory.PcfConfig.Logger.PCF.DebugLevel); err != nil {
				logger.InitLog.Warnf("PCF Log level [%s] is invalid, set to [info] level",
					factory.PcfConfig.Logger.PCF.DebugLevel)
				logger.SetLogLevel(zap.InfoLevel)
			} else {
				logger.InitLog.Infof("PCF Log level is set to [%s] level", level)
				logger.SetLogLevel(level)
			}
		} else {
			logger.InitLog.Infoln("PCF Log level is default set to [info] level")
			logger.SetLogLevel(zap.InfoLevel)
		}
	}

	if factory.PcfConfig.Logger.OpenApi != nil {
		if factory.PcfConfig.Logger.OpenApi.DebugLevel != "" {
			if level, err := zapcore.ParseLevel(factory.PcfConfig.Logger.OpenApi.DebugLevel); err != nil {
				openapiLogger.OpenapiLog.Warnf("OpenAPI Log level [%s] is invalid, set to [info] level",
					factory.PcfConfig.Logger.OpenApi.DebugLevel)
				openapiLogger.SetLogLevel(zap.InfoLevel)
			} else {
				openapiLogger.SetLogLevel(level)
			}
		} else {
			openapiLogger.OpenapiLog.Warnln("OpenAPI Log level not set. Default set to [info] level")
			openapiLogger.SetLogLevel(zap.InfoLevel)
		}
	}
}

func (pcf *PCF) FilterCli(c *cli.Command) (args []string) {
	for _, flag := range pcf.GetCliCmd() {
		name := flag.Names()[0]
		value := fmt.Sprint(c.Generic(name))
		if value == "" {
			continue
		}

		args = append(args, "--"+name, value)
	}
	return args
}

func (pcf *PCF) Start() {
	logger.InitLog.Infoln("server started")
	router := utilLogger.NewGinWithZap(logger.GinLog)

	bdtpolicy.AddService(router)
	smpolicy.AddService(router)
	ampolicy.AddService(router)
	uepolicy.AddService(router)
	policyauthorization.AddService(router)
	httpcallback.AddService(router)
	oam.AddService(router)
	callback.AddService(router)

	go metrics.InitMetrics()

	router.Use(cors.New(cors.Config{
		AllowMethods: []string{"GET", "POST", "OPTIONS", "PUT", "PATCH", "DELETE"},
		AllowHeaders: []string{
			"Origin", "Content-Length", "Content-Type", "User-Agent",
			"Referrer", "Host", "Token", "X-Requested-With",
		},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowAllOrigins:  true,
		MaxAge:           86400,
	}))

	if err := notifyevent.RegisterNotifyDispatcher(); err != nil {
		logger.InitLog.Errorln("register NotifyDispatcher error")
	}

	self := context.PCF_Self()
	util.InitpcfContext(self)

	addr := fmt.Sprintf("%s:%d", self.BindingIPv4, self.SBIPort)

	if self.EnableNrfCaching {
		logger.InitLog.Infoln("enable NRF caching feature")
		nrfCache.InitNrfCaching(self.NrfCacheEvictionInterval*time.Second, consumer.SendNfDiscoveryToNrf)
	}
	// Attempt NRF Registration until success
	go pcf.RegisterNF()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChannel
		pcf.Terminate()
		os.Exit(0)
	}()

	sslLog := filepath.Dir(factory.PcfConfig.CfgLocation) + "/sslkey.log"
	server, err := http2_util.NewServer(addr, sslLog, router)
	if server == nil {
		logger.InitLog.Errorf("initialize HTTP server failed: %+v", err)
		return
	}

	if err != nil {
		logger.InitLog.Warnf("initialize HTTP server: +%v", err)
	}

	serverScheme := factory.PcfConfig.Configuration.Sbi.Scheme
	switch serverScheme {
	case "http":
		err = server.ListenAndServe()
	case "https":
		err = server.ListenAndServeTLS(self.PEM, self.Key)
	default:
		logger.InitLog.Fatalf("HTTP server setup failed: invalid server scheme %+v", serverScheme)
		return
	}

	if err != nil {
		logger.InitLog.Fatalf("HTTP server setup failed: %+v", err)
	}
}

func (pcf *PCF) Exec(c *cli.Command) error {
	logger.InitLog.Debugln("args:", c.String("cfg"))
	args := pcf.FilterCli(c)
	logger.InitLog.Debugln("filter:", args)
	command := exec.Command("pcf", args...)

	stdout, err := command.StdoutPipe()
	if err != nil {
		logger.InitLog.Fatalln(err)
	}
	wg := sync.WaitGroup{}
	wg.Add(4)
	go func() {
		in := bufio.NewScanner(stdout)
		for in.Scan() {
			logger.InitLog.Infoln(in.Text())
		}
		wg.Done()
	}()

	stderr, err := command.StderrPipe()
	if err != nil {
		logger.InitLog.Fatalln(err)
	}
	go func() {
		in := bufio.NewScanner(stderr)
		logger.InitLog.Infoln("PCF log start")
		for in.Scan() {
			logger.InitLog.Infoln(in.Text())
		}
		wg.Done()
	}()

	go func() {
		logger.InitLog.Infoln("PCF start")
		if err = command.Start(); err != nil {
			logger.InitLog.Errorf("command.Start() error: %v", err)
		}
		logger.InitLog.Infoln("PCF end")
		wg.Done()
	}()

	wg.Wait()

	return err
}

func (pcf *PCF) StartKeepAliveTimer(nfProfile models.NfProfile) {
	KeepAliveTimerMutex.Lock()
	defer KeepAliveTimerMutex.Unlock()
	pcf.StopKeepAliveTimer()
	if nfProfile.HeartBeatTimer == 0 {
		// heartbeat timer value set to 60 sec
		nfProfile.HeartBeatTimer = 60
	}
	logger.InitLog.Infof("started KeepAlive Timer: %v sec", nfProfile.HeartBeatTimer)
	// AfterFunc starts timer and waits for KeepAliveTimer to elapse and then calls pcf.UpdateNF function
	KeepAliveTimer = time.AfterFunc(time.Duration(nfProfile.HeartBeatTimer)*time.Second, pcf.UpdateNF)
}

func (pcf *PCF) StopKeepAliveTimer() {
	if KeepAliveTimer != nil {
		logger.InitLog.Infof("stopped KeepAlive timer")
		KeepAliveTimer.Stop()
		KeepAliveTimer = nil
	}
}

func (pcf *PCF) Terminate() {
	logger.InitLog.Infof("terminating PCF")
	// deregister with NRF
	problemDetails, err := consumer.SendDeregisterNFInstance()
	if problemDetails != nil {
		logger.InitLog.Errorf("deregister NF instance Failed Problem[%+v]", problemDetails)
	} else if err != nil {
		logger.InitLog.Errorf("deregister NF instance Error[%+v]", err)
	} else {
		logger.InitLog.Infoln("deregister from NRF successfully")
	}
	logger.InitLog.Infoln("PCF terminated")
}

func (pcf *PCF) BuildAndSendRegisterNFInstance() (models.NfProfile, error) {
	self := context.PCF_Self()
	profile, err := consumer.BuildNFInstance(self)
	if err != nil {
		logger.InitLog.Errorf("build PCF Profile Error: %v", err)
		return profile, err
	}
	logger.InitLog.Infof("PCF Profile Registering to NRF: %v", profile)
	// Indefinite attempt to register until success
	profile, _, self.NfId, err = consumer.SendRegisterNFInstance(self.NrfUri, self.NfId, profile)
	return profile, err
}

func (pcf *PCF) RegisterNF() {
	for {
		msg := <-ConfigPodTrigger
		// wait till Config pod updates config
		if msg {
			logger.InitLog.Infof("config update trigger %v received in PCF App", msg)
			profile, err := pcf.BuildAndSendRegisterNFInstance()
			if err != nil {
				logger.InitLog.Errorf("PCF register to NRF Error[%s]", err.Error())
			} else {
				pcf.StartKeepAliveTimer(profile)
				// NRF Registration Successful, Trigger for UDR Discovery
				pcf.DiscoverUdr()
			}
		} else {
			// stopping keepAlive timer
			KeepAliveTimerMutex.Lock()
			pcf.StopKeepAliveTimer()
			KeepAliveTimerMutex.Unlock()
			logger.InitLog.Infof("PCF is not having Minimum Config to Register/Update to NRF")
			problemDetails, err := consumer.SendDeregisterNFInstance()
			if problemDetails != nil {
				logger.InitLog.Errorf("PCF Deregister Instance to NRF failed, Problem: [+%v]", problemDetails)
			}
			if err != nil {
				logger.InitLog.Errorf("PCF Deregister Instance to NRF Error[%s]", err.Error())
			} else {
				logger.InitLog.Infoln("deregister from NRF successfully")
			}
		}
	}
}

// UpdateNF is the callback function, this is called when keepalive timer elapsed
func (pcf *PCF) UpdateNF() {
	KeepAliveTimerMutex.Lock()
	defer KeepAliveTimerMutex.Unlock()
	if KeepAliveTimer == nil {
		logger.InitLog.Warnf("KeepAlive timer has been stopped")
		return
	}
	// setting default value 60 sec
	var heartBeatTimer int32 = 60
	pitem := models.PatchItem{
		Op:    "replace",
		Path:  "/nfStatus",
		Value: "REGISTERED",
	}
	var patchItem []models.PatchItem
	patchItem = append(patchItem, pitem)
	nfProfile, problemDetails, err := consumer.SendUpdateNFInstance(patchItem)
	if problemDetails != nil {
		logger.InitLog.Errorf("PCF update to NRF ProblemDetails[%v]", problemDetails)
		// 5xx response from NRF, 404 Not Found, 400 Bad Request
		if (problemDetails.Status/100) == 5 ||
			problemDetails.Status == 404 || problemDetails.Status == 400 {
			// register with NRF full profile
			nfProfile, err = pcf.BuildAndSendRegisterNFInstance()
			if err != nil {
				logger.InitLog.Errorf("PCF register to NRF Error[%s]", err.Error())
			}
		}
	} else if err != nil {
		logger.InitLog.Errorf("PCF update to NRF Error[%s]", err.Error())
		nfProfile, err = pcf.BuildAndSendRegisterNFInstance()
		if err != nil {
			logger.InitLog.Errorf("PCF register to NRF Error[%s]", err.Error())
		}
	}

	if nfProfile.HeartBeatTimer != 0 {
		// use hearbeattimer value with received timer value from NRF
		heartBeatTimer = nfProfile.HeartBeatTimer
	}
	logger.InitLog.Debugf("restarted KeepAlive Timer: %v sec", heartBeatTimer)
	// restart timer with received HeartBeatTimer value
	KeepAliveTimer = time.AfterFunc(time.Duration(heartBeatTimer)*time.Second, pcf.UpdateNF)
}

func (pcf *PCF) DiscoverUdr() {
	self := context.PCF_Self()
	param := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{
		ServiceNames: optional.NewInterface([]models.ServiceName{models.ServiceName_NUDR_DR}),
	}
	if resp, err := consumer.SendSearchNFInstances(self.NrfUri, models.NfType_UDR, models.NfType_PCF, &param); err != nil {
		logger.InitLog.Errorln(err)
	} else {
		for _, nfProfile := range resp.NfInstances {
			udruri := util.SearchNFServiceUri(nfProfile, models.ServiceName_NUDR_DR, models.NfServiceStatus_REGISTERED)
			if udruri != "" {
				self.SetDefaultUdrURI(udruri)
				break
			}
		}
	}
}

func ImsiExistInDeviceGroup(devGroup *protos.DeviceGroup, imsi string) bool {
	for _, i := range devGroup.Imsi {
		if i == imsi {
			return true
		}
	}
	return false
}

func GetBitRateUnit(val int64) (int64, string) {
	unit := " Kbps"
	if val < 1000 {
		logger.GrpcLog.Warnf("configured value [%v] is lesser than 1000 bps, so setting 1 Kbps", val)
		val = 1
		return val, unit
	}
	if val >= 0xFFFF {
		val = val / 1000
		unit = " Kbps"
		if val >= 0xFFFF {
			val = val / 1000
			unit = " Mbps"
		}
		if val >= 0xFFFF {
			val = val / 1000
			unit = " Gbps"
		}
	} else {
		// minimum supported is kbps by SMF/UE
		val = val / 1000
	}

	return val, unit
}

func getSessionRule(devGroup *protos.DeviceGroup) (sessionRule *models.SessionRule) {
	sessionRule = &models.SessionRule{}
	qos := devGroup.IpDomainDetails.UeDnnQos
	if qos.TrafficClass != nil {
		sessionRule.AuthDefQos = &models.AuthorizedDefaultQos{
			Var5qi: qos.TrafficClass.Qci,
			Arp:    &models.Arp{PriorityLevel: qos.TrafficClass.Arp},
			// PriorityLevel:
		}
	}
	ul, uunit := GetBitRateUnit(qos.DnnMbrUplink)
	dl, dunit := GetBitRateUnit(qos.DnnMbrDownlink)
	sessionRule.AuthSessAmbr = &models.Ambr{
		Uplink:   strconv.FormatInt(ul, 10) + uunit,
		Downlink: strconv.FormatInt(dl, 10) + dunit,
	}
	return sessionRule
}

func getPccRules(slice *protos.NetworkSlice, sessionRule *models.SessionRule) (pccPolicy context.PccPolicy) {
	if slice.AppFilters == nil || slice.AppFilters.PccRuleBase == nil {
		logger.GrpcLog.Warnf("PccRules not exist in slice: %v", slice.Name)
		return pccPolicy
	}
	pccPolicy.IdGenerator = idgenerator.NewGenerator(1, math.MaxInt64)
	for _, pccrule := range slice.AppFilters.PccRuleBase {
		id, err := pccPolicy.IdGenerator.Allocate()
		if err != nil {
			logger.GrpcLog.Errorf("IdGenerator allocation failed: %v", err)
		}
		var rule models.PccRule
		var qos models.QosData
		rule.PccRuleId = strconv.FormatInt(id, 10)
		rule.Precedence = pccrule.Priority
		if pccrule.Qos != nil {
			qos.QosId = strconv.FormatInt(id, 10)
			qos.Var5qi = pccrule.Qos.Var5Qi
			if pccrule.Qos.MaxbrUl != 0 {
				ul, unit := GetBitRateUnit(int64(pccrule.Qos.MaxbrUl))
				qos.MaxbrUl = strconv.FormatInt(ul, 10) + unit
			}
			if pccrule.Qos.MaxbrDl != 0 {
				dl, unit := GetBitRateUnit(int64(pccrule.Qos.MaxbrDl))
				qos.MaxbrDl = strconv.FormatInt(dl, 10) + unit
			}
			if pccrule.Qos.GbrUl != 0 {
				ul, unit := GetBitRateUnit(int64(pccrule.Qos.GbrUl))
				qos.GbrUl = strconv.FormatInt(ul, 10) + unit
			}
			if pccrule.Qos.GbrDl != 0 {
				dl, unit := GetBitRateUnit(int64(pccrule.Qos.GbrDl))
				qos.GbrDl = strconv.FormatInt(dl, 10) + unit
			}
			if pccrule.Qos.Arp != nil {
				qos.Arp = &models.Arp{PriorityLevel: pccrule.Qos.Arp.PL}
				switch pccrule.Qos.Arp.PC {
				case protos.PccArpPc_NOT_PREEMPT:
					qos.Arp.PreemptCap = models.PreemptionCapability_NOT_PREEMPT
				case protos.PccArpPc_MAY_PREEMPT:
					qos.Arp.PreemptCap = models.PreemptionCapability_MAY_PREEMPT
				}
				switch pccrule.Qos.Arp.PV {
				case protos.PccArpPv_NOT_PREEMPTABLE:
					qos.Arp.PreemptVuln = models.PreemptionVulnerability_NOT_PREEMPTABLE
				case protos.PccArpPv_PREEMPTABLE:
					qos.Arp.PreemptVuln = models.PreemptionVulnerability_PREEMPTABLE
				}
			}
			if pccrule.Qos.MaxbrUl == 0 && pccrule.Qos.MaxbrDl == 0 && pccrule.Qos.GbrUl == 0 && pccrule.Qos.GbrDl == 0 {
				// getting from sessionrule
				qos.MaxbrUl = sessionRule.AuthSessAmbr.Uplink
				qos.MaxbrDl = sessionRule.AuthSessAmbr.Downlink
			}
			//rule.RefQosData = append(rule.RefQosData, qos.QosId)
			//if pccPolicy.QosDecs == nil {
			//	pccPolicy.QosDecs = make(map[string]*models.QosData)
			//}
			//pccPolicy.QosDecs[qos.QosId] = &qos
		}
		for _, pflow := range pccrule.FlowInfos {
			var flow models.FlowInformation
			flow.FlowDescription = pflow.FlowDesc
			// flow.TosTrafficClass = pflow.TosTrafficClass
			id, err := pccPolicy.IdGenerator.Allocate()
			if err != nil {
				logger.GrpcLog.Errorf("IdGenerator allocation failed: %v", err)
			}
			flow.PackFiltId = strconv.FormatInt(id, 10)

			switch pflow.FlowDir {
			case protos.PccFlowDirection_DOWNLINK:
				flow.FlowDirection = models.FlowDirectionRm_DOWNLINK
			case protos.PccFlowDirection_UPLINK:
				flow.FlowDirection = models.FlowDirectionRm_UPLINK
			case protos.PccFlowDirection_BIDIRECTIONAL:
				flow.FlowDirection = models.FlowDirectionRm_BIDIRECTIONAL
			case protos.PccFlowDirection_UNSPECIFIED:
				flow.FlowDirection = models.FlowDirectionRm_UNSPECIFIED
			}
			if strings.HasSuffix(flow.FlowDescription, "any to assigned") ||
				strings.HasSuffix(flow.FlowDescription, "any to assigned ") {
				qos.DefQosFlowIndication = true
			}
			// traffic control info set based on flow at present
			var tcData models.TrafficControlData
			tcData.TcId = "TcId-" + strconv.FormatInt(id, 10)

			switch pflow.FlowStatus {
			case protos.PccFlowStatus_ENABLED:
				tcData.FlowStatus = models.FlowStatus_ENABLED
			case protos.PccFlowStatus_DISABLED:
				tcData.FlowStatus = models.FlowStatus_DISABLED
			}

			rule.RefTcData = append(rule.RefTcData, tcData.TcId)
			if pccPolicy.TraffContDecs == nil {
				pccPolicy.TraffContDecs = make(map[string]*models.TrafficControlData)
			}
			pccPolicy.TraffContDecs[tcData.TcId] = &tcData

			rule.FlowInfos = append(rule.FlowInfos, flow)
		}
		if pccPolicy.QosDecs == nil {
			pccPolicy.QosDecs = make(map[string]*models.QosData)
		}
		if ok, q := findQosData(pccPolicy.QosDecs, qos); ok {
			rule.RefQosData = append(rule.RefQosData, q.QosId)
		} else {
			rule.RefQosData = append(rule.RefQosData, qos.QosId)
			pccPolicy.QosDecs[qos.QosId] = &qos
		}
		if pccPolicy.PccRules == nil {
			pccPolicy.PccRules = make(map[string]*models.PccRule)
		}
		pccPolicy.PccRules[pccrule.RuleId] = &rule
	}

	return pccPolicy
}

func findQosData(qosdecs map[string]*models.QosData, qos models.QosData) (bool, *models.QosData) {
	for _, q := range qosdecs {
		if q.Var5qi == qos.Var5qi && q.MaxbrUl == qos.MaxbrUl && q.MaxbrDl == qos.MaxbrDl &&
			q.GbrUl == qos.GbrUl && q.GbrDl == qos.GbrDl && q.Qnc == qos.Qnc &&
			q.PriorityLevel == qos.PriorityLevel && q.AverWindow == qos.AverWindow &&
			q.MaxDataBurstVol == qos.MaxDataBurstVol && q.ReflectiveQos == qos.ReflectiveQos &&
			q.SharingKeyDl == qos.SharingKeyDl && q.SharingKeyUl == qos.SharingKeyUl &&
			q.MaxPacketLossRateDl == qos.MaxPacketLossRateDl && q.MaxPacketLossRateUl == qos.MaxPacketLossRateUl &&
			q.DefQosFlowIndication == qos.DefQosFlowIndication {
			if q.Arp != nil && qos.Arp != nil && *q.Arp == *qos.Arp {
				return true, q
			}
		}
	}
	return false, nil
}

func (pcf *PCF) CreatePolicyDataforImsi(imsi string, sliceid string, dnn string, sessionrule *models.SessionRule, slice *protos.NetworkSlice) {
	self := context.PCF_Self()
	self.PcfSubscriberPolicyData[imsi] = &context.PcfSubscriberPolicyData{}
	policyData := self.PcfSubscriberPolicyData[imsi]
	policyData.CtxLog = logger.CtxLog.With(logger.FieldSupi, "imsi-"+imsi)

	policyData.PccPolicy = make(map[string]*context.PccPolicy)
	policyData.PccPolicy[sliceid] = &context.PccPolicy{
		PccRules: make(map[string]*models.PccRule),
		QosDecs:  make(map[string]*models.QosData), TraffContDecs: make(map[string]*models.TrafficControlData),
		SessionPolicy: make(map[string]*context.SessionPolicy), IdGenerator: nil,
	}

	policyData.PccPolicy[sliceid].SessionPolicy[dnn] = &context.SessionPolicy{
		SessionRules:           make(map[string]*models.SessionRule),
		SessionRuleIdGenerator: idgenerator.NewGenerator(1, math.MaxInt16),
	}

	id, err := policyData.PccPolicy[sliceid].SessionPolicy[dnn].SessionRuleIdGenerator.Allocate()
	if err != nil {
		logger.GrpcLog.Errorf("SessionRuleIdGenerator allocation failed: %v", err)
	}

	sessionrule.SessRuleId = dnn + "-" + strconv.Itoa(int(id))
	policyData.PccPolicy[sliceid].SessionPolicy[dnn].SessionRules[sessionrule.SessRuleId] = sessionrule
	pccPolicy := getPccRules(slice, sessionrule)

	for index, element := range pccPolicy.PccRules {
		policyData.PccPolicy[sliceid].PccRules[index] = element
	}
	for index, element := range pccPolicy.QosDecs {
		policyData.PccPolicy[sliceid].QosDecs[index] = element
	}
	for index, element := range pccPolicy.TraffContDecs {
		policyData.PccPolicy[sliceid].TraffContDecs[index] = element
	}
	policyData.CtxLog.Infof("Policy Data: %v for IMSI: %v", policyData, imsi)
}

func (pcf *PCF) UpdatePcfSubscriberPolicyData(slice *protos.NetworkSlice) {
	self := context.PCF_Self()
	sliceid := slice.Nssai.Sst + slice.Nssai.Sd
	switch slice.OperationType {
	case protos.OpType_SLICE_ADD:
		logger.GrpcLog.Infoln("received Slice with OperationType: Add from ConfigPod")
		for _, devgroup := range slice.DeviceGroup {
			var sessionrule *models.SessionRule
			var dnn string
			if devgroup.IpDomainDetails == nil || devgroup.IpDomainDetails.UeDnnQos == nil {
				logger.GrpcLog.Warnf("ip details or qos details in ipdomain not exist for device group: %v", devgroup.Name)
				continue
			}
			dnn = devgroup.IpDomainDetails.DnnName
			sessionrule = getSessionRule(devgroup)
			for _, imsi := range devgroup.Imsi {
				pcf.CreatePolicyDataforImsi(imsi, sliceid, dnn, sessionrule, slice)
			}
		}

	case protos.OpType_SLICE_UPDATE:
		logger.GrpcLog.Infoln("received Slice with OperationType: Update from ConfigPod")
		for _, devgroup := range slice.DeviceGroup {
			var sessionrule *models.SessionRule
			var dnn string
			if devgroup.IpDomainDetails == nil || devgroup.IpDomainDetails.UeDnnQos == nil {
				logger.GrpcLog.Warnf("ip details or qos details in ipdomain not exist for device group: %v", devgroup.Name)
				continue
			}

			dnn = devgroup.IpDomainDetails.DnnName
			sessionrule = getSessionRule(devgroup)
			for _, imsi := range devgroup.Imsi {
				pcf.CreatePolicyDataforImsi(imsi, sliceid, dnn, sessionrule, slice)
			}
		}

		for _, imsi := range slice.DeletedImsis {
			policyData, ok := self.PcfSubscriberPolicyData[imsi]
			if !ok {
				logger.GrpcLog.Warnf("imsi: %v not exist in SubscriberPolicyData", imsi)
				continue
			}
			_, ok = policyData.PccPolicy[sliceid]
			if !ok {
				logger.GrpcLog.Errorf("PccPolicy for the slice: %v not exist in SubscriberPolicyData", sliceid)
				continue
			}
			// sessionrules, pccrules if exist in slice, implicitly deletes all sessionrules, pccrules for this sliceid
			policyData.CtxLog.Infof("slice: %v deleted from SubscriberPolicyData", sliceid)
			delete(policyData.PccPolicy, sliceid)
			if len(policyData.PccPolicy) == 0 {
				policyData.CtxLog.Infoln("subscriber deleted from PcfSubscriberPolicyData map")
				delete(self.PcfSubscriberPolicyData, imsi)
			}
		}

	case protos.OpType_SLICE_DELETE:
		logger.GrpcLog.Infoln("received Slice with OperationType: delete from ConfigPod")
		for _, imsi := range slice.DeletedImsis {
			policyData, ok := self.PcfSubscriberPolicyData[imsi]
			if !ok {
				logger.GrpcLog.Errorf("imsi: %v not exist in SubscriberPolicyData", imsi)
				continue
			}
			_, ok = policyData.PccPolicy[sliceid]
			if !ok {
				logger.GrpcLog.Errorf("PccPolicy for the slice: %v not exist in SubscriberPolicyData", sliceid)
				continue
			}
			policyData.CtxLog.Infof("slice: %v deleted from SubscriberPolicyData", sliceid)
			delete(policyData.PccPolicy, sliceid)
			if len(policyData.PccPolicy) == 0 {
				policyData.CtxLog.Infoln("subscriber deleted from PcfSubscriberPolicyData map")
				delete(self.PcfSubscriberPolicyData, imsi)
			}
		}
	}
}

func (pcf *PCF) UpdateDnnList(ns *protos.NetworkSlice) {
	sliceid := ns.Nssai.Sst + ns.Nssai.Sd
	pcfContext := context.PCF_Self()
	pcfConfig := factory.PcfConfig.Configuration
	switch ns.OperationType {
	case protos.OpType_SLICE_ADD:
		fallthrough
	case protos.OpType_SLICE_UPDATE:
		var dnnList []string
		for _, devgroup := range ns.DeviceGroup {
			if devgroup.IpDomainDetails != nil {
				dnnList = append(dnnList, devgroup.IpDomainDetails.DnnName)
			}
		}
		if pcfConfig.DnnList == nil {
			pcfConfig.DnnList = make(map[string][]string)
		}
		pcfConfig.DnnList[sliceid] = dnnList
	case protos.OpType_SLICE_DELETE:
		delete(pcfConfig.DnnList, sliceid)
	}
	s := fmt.Sprintf("Updated Slice level DnnList[%v]: ", sliceid)
	for _, dnn := range pcfConfig.DnnList[sliceid] {
		s += fmt.Sprintf("%v ", dnn)
	}
	logger.GrpcLog.Infoln(s)

	pcfContext.DnnList = nil
	for _, slice := range pcfConfig.DnnList {
		for _, dnn := range slice {
			var found bool
			for _, d := range pcfContext.DnnList {
				if d == dnn {
					found = true
				}
			}
			if !found {
				pcfContext.DnnList = append(pcfContext.DnnList, dnn)
			}
		}
	}
	logger.GrpcLog.Infof("DnnList present in PCF: %v", pcfContext.DnnList)
}

func (pcf *PCF) UpdatePlmnList(ns *protos.NetworkSlice) {
	sliceid := ns.Nssai.Sst + ns.Nssai.Sd
	pcfContext := context.PCF_Self()
	pcfConfig := factory.PcfConfig.Configuration
	switch ns.OperationType {
	case protos.OpType_SLICE_ADD:
		fallthrough
	case protos.OpType_SLICE_UPDATE:
		temp := factory.PlmnSupportItem{}
		if ns.Site.Plmn != nil {
			temp.PlmnId.Mcc = ns.Site.Plmn.Mcc
			temp.PlmnId.Mnc = ns.Site.Plmn.Mnc
		}
		if pcfConfig.SlicePlmn == nil {
			pcfConfig.SlicePlmn = make(map[string]factory.PlmnSupportItem)
		}
		pcfConfig.SlicePlmn[sliceid] = temp
	case protos.OpType_SLICE_DELETE:
		delete(pcfConfig.SlicePlmn, sliceid)
	}
	s := fmt.Sprintf("Updated Slice level Plmn[%v]: %v", sliceid, pcfConfig.SlicePlmn[sliceid])
	logger.GrpcLog.Infoln(s)
	pcfContext.PlmnList = nil
	for _, plmn := range pcfConfig.SlicePlmn {
		var found bool
		for _, p := range pcfContext.PlmnList {
			if p == plmn {
				found = true
				break
			}
		}
		if !found {
			pcfContext.PlmnList = append(pcfContext.PlmnList, plmn)
		}
	}
	logger.GrpcLog.Infof("PlmnList present in PCF: %v", pcfContext.PlmnList)
}

func (pcf *PCF) UpdateConfig(commChannel chan *protos.NetworkSliceResponse) bool {
	var minConfig bool
	pcfContext := context.PCF_Self()
	for rsp := range commChannel {
		logger.GrpcLog.Infoln("received UpdateConfig in the pcf app:", rsp)
		for _, ns := range rsp.NetworkSlice {
			logger.GrpcLog.Infoln("network slice name:", ns.Name)

			// Update Qos Info
			// Update/Create/Delete PcfSubscriberPolicyData
			pcf.UpdatePcfSubscriberPolicyData(ns)

			pcf.UpdateDnnList(ns)

			if ns.Site != nil {
				site := ns.Site
				logger.GrpcLog.Infof("network slice [%v] has site name: %v", ns.Nssai.Sst+ns.Nssai.Sd, site.SiteName)
				if site.Plmn != nil {
					pcf.UpdatePlmnList(ns)
				} else {
					logger.GrpcLog.Infof("Plmn not present in the sitename: %v of Slice: %v", site.SiteName, ns.Nssai.Sst+ns.Nssai.Sd)
				}
			}
		}
		// minConfig is 'true' when one slice is configured at least.
		// minConfig is 'false' when no slice configuration.
		// check PlmnList for each configuration update from Roc/Simapp.
		if !minConfig {
			// For each slice Plmn is the mandatory parameter, checking PlmnList length is greater than zero
			// setting minConfig to true
			if len(pcfContext.PlmnList) > 0 {
				minConfig = true
				ConfigPodTrigger <- true
				// Start Heart Beat timer for periodic config updates to NRF
				logger.GrpcLog.Infoln("send config trigger to main routine first time config")
			}
		} else if minConfig { // one or more slices are configured hence minConfig is true
			// minConfig is true but PlmnList is '0' means slices were configured then deleted.
			if len(pcfContext.PlmnList) == 0 {
				minConfig = false
				ConfigPodTrigger <- false
				logger.GrpcLog.Infoln("send config trigger to main routine config deleted")
			} else {
				// configuration update from simapp/RoC
				ConfigPodTrigger <- true
				logger.GrpcLog.Infoln("send config trigger to main routine config updated")
			}
		}
	}
	return true
}
