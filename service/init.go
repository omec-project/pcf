// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
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
	"strconv"
	"sync"
	"syscall"

	"github.com/antihax/optional"
	"github.com/gin-contrib/cors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/free5gc/http2_util"
	"github.com/free5gc/idgenerator"
	"github.com/free5gc/logger_util"
	"github.com/free5gc/openapi/Nnrf_NFDiscovery"
	openApiLogger "github.com/free5gc/openapi/logger"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/path_util"
	pathUtilLogger "github.com/free5gc/path_util/logger"
	"github.com/free5gc/pcf/ampolicy"
	"github.com/free5gc/pcf/bdtpolicy"
	"github.com/free5gc/pcf/consumer"
	"github.com/free5gc/pcf/context"
	"github.com/free5gc/pcf/factory"
	"github.com/free5gc/pcf/httpcallback"
	"github.com/free5gc/pcf/internal/notifyevent"
	"github.com/free5gc/pcf/logger"
	"github.com/free5gc/pcf/oam"
	"github.com/free5gc/pcf/policyauthorization"
	"github.com/free5gc/pcf/smpolicy"
	"github.com/free5gc/pcf/uepolicy"
	"github.com/free5gc/pcf/util"
	"github.com/omec-project/config5g/proto/client"
	protos "github.com/omec-project/config5g/proto/sdcoreConfig"
)

type PCF struct{}

type (
	// Config information.
	Config struct {
		pcfcfg string
	}
)

var ConfigPodTrigger chan bool

func init() {
	ConfigPodTrigger = make(chan bool)
}

var config Config

var pcfCLi = []cli.Flag{
	cli.StringFlag{
		Name:  "free5gccfg",
		Usage: "common config file",
	},
	cli.StringFlag{
		Name:  "pcfcfg",
		Usage: "config file",
	},
}

var initLog *logrus.Entry

func init() {
	initLog = logger.InitLog
}

func (*PCF) GetCliCmd() (flags []cli.Flag) {
	return pcfCLi
}

func (pcf *PCF) Initialize(c *cli.Context) error {
	config = Config{
		pcfcfg: c.String("pcfcfg"),
	}
	if config.pcfcfg != "" {
		if err := factory.InitConfigFactory(config.pcfcfg); err != nil {
			return err
		}
	} else {
		DefaultPcfConfigPath := path_util.Free5gcPath("free5gc/config/pcfcfg.yaml")
		if err := factory.InitConfigFactory(DefaultPcfConfigPath); err != nil {
			return err
		}
	}

	pcf.setLogLevel()

	if err := factory.CheckConfigVersion(); err != nil {
		return err
	}

	roc := os.Getenv("MANAGED_BY_CONFIG_POD")
	if roc == "true" {
		initLog.Infoln("MANAGED_BY_CONFIG_POD is true")
		gClient := client.ConnectToConfigServer("webui:9876")
		commChannel := gClient.PublishOnConfigChange(true)
		go pcf.updateConfig(commChannel)
	} else {
		go func() {
			initLog.Infoln("Use helm chart config ")
			ConfigPodTrigger <- true
		}()
	}
	return nil
}

func (pcf *PCF) setLogLevel() {
	if factory.PcfConfig.Logger == nil {
		initLog.Warnln("PCF config without log level setting!!!")
		return
	}

	if factory.PcfConfig.Logger.PCF != nil {
		if factory.PcfConfig.Logger.PCF.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.PcfConfig.Logger.PCF.DebugLevel); err != nil {
				initLog.Warnf("PCF Log level [%s] is invalid, set to [info] level",
					factory.PcfConfig.Logger.PCF.DebugLevel)
				logger.SetLogLevel(logrus.InfoLevel)
			} else {
				initLog.Infof("PCF Log level is set to [%s] level", level)
				logger.SetLogLevel(level)
			}
		} else {
			initLog.Infoln("PCF Log level is default set to [info] level")
			logger.SetLogLevel(logrus.InfoLevel)
		}
		logger.SetReportCaller(factory.PcfConfig.Logger.PCF.ReportCaller)
	}

	if factory.PcfConfig.Logger.PathUtil != nil {
		if factory.PcfConfig.Logger.PathUtil.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.PcfConfig.Logger.PathUtil.DebugLevel); err != nil {
				pathUtilLogger.PathLog.Warnf("PathUtil Log level [%s] is invalid, set to [info] level",
					factory.PcfConfig.Logger.PathUtil.DebugLevel)
				pathUtilLogger.SetLogLevel(logrus.InfoLevel)
			} else {
				pathUtilLogger.SetLogLevel(level)
			}
		} else {
			pathUtilLogger.PathLog.Warnln("PathUtil Log level not set. Default set to [info] level")
			pathUtilLogger.SetLogLevel(logrus.InfoLevel)
		}
		pathUtilLogger.SetReportCaller(factory.PcfConfig.Logger.PathUtil.ReportCaller)
	}

	if factory.PcfConfig.Logger.OpenApi != nil {
		if factory.PcfConfig.Logger.OpenApi.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.PcfConfig.Logger.OpenApi.DebugLevel); err != nil {
				openApiLogger.OpenApiLog.Warnf("OpenAPI Log level [%s] is invalid, set to [info] level",
					factory.PcfConfig.Logger.OpenApi.DebugLevel)
				openApiLogger.SetLogLevel(logrus.InfoLevel)
			} else {
				openApiLogger.SetLogLevel(level)
			}
		} else {
			openApiLogger.OpenApiLog.Warnln("OpenAPI Log level not set. Default set to [info] level")
			openApiLogger.SetLogLevel(logrus.InfoLevel)
		}
		openApiLogger.SetReportCaller(factory.PcfConfig.Logger.OpenApi.ReportCaller)
	}
}

func (pcf *PCF) FilterCli(c *cli.Context) (args []string) {
	for _, flag := range pcf.GetCliCmd() {
		name := flag.GetName()
		value := fmt.Sprint(c.Generic(name))
		if value == "" {
			continue
		}

		args = append(args, "--"+name, value)
	}
	return args
}

func (pcf *PCF) Start() {
	initLog.Infoln("Server started")
	router := logger_util.NewGinWithLogrus(logger.GinLog)

	bdtpolicy.AddService(router)
	smpolicy.AddService(router)
	ampolicy.AddService(router)
	uepolicy.AddService(router)
	policyauthorization.AddService(router)
	httpcallback.AddService(router)
	oam.AddService(router)

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
		initLog.Error("Register NotifyDispatcher Error")
	}

	self := context.PCF_Self()
	util.InitpcfContext(self)

	addr := fmt.Sprintf("%s:%d", self.BindingIPv4, self.SBIPort)

	//Attempt NRF Registration until success
	go pcf.registerNF()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChannel
		pcf.Terminate()
		os.Exit(0)
	}()

	server, err := http2_util.NewServer(addr, util.PCF_LOG_PATH, router)
	if server == nil {
		initLog.Errorf("Initialize HTTP server failed: %+v", err)
		return
	}

	if err != nil {
		initLog.Warnf("Initialize HTTP server: +%v", err)
	}

	serverScheme := factory.PcfConfig.Configuration.Sbi.Scheme
	if serverScheme == "http" {
		err = server.ListenAndServe()
	} else if serverScheme == "https" {
		err = server.ListenAndServeTLS(util.PCF_PEM_PATH, util.PCF_KEY_PATH)
	}

	if err != nil {
		initLog.Fatalf("HTTP server setup failed: %+v", err)
	}
}

func (pcf *PCF) Exec(c *cli.Context) error {
	initLog.Traceln("args:", c.String("pcfcfg"))
	args := pcf.FilterCli(c)
	initLog.Traceln("filter: ", args)
	command := exec.Command("./pcf", args...)

	stdout, err := command.StdoutPipe()
	if err != nil {
		initLog.Fatalln(err)
	}
	wg := sync.WaitGroup{}
	wg.Add(4)
	go func() {
		in := bufio.NewScanner(stdout)
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	stderr, err := command.StderrPipe()
	if err != nil {
		initLog.Fatalln(err)
	}
	go func() {
		in := bufio.NewScanner(stderr)
		fmt.Println("PCF log start")
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	go func() {
		fmt.Println("PCF start")
		if err = command.Start(); err != nil {
			fmt.Printf("command.Start() error: %v", err)
		}
		fmt.Println("PCF end")
		wg.Done()
	}()

	wg.Wait()

	return err
}

func (pcf *PCF) Terminate() {
	logger.InitLog.Infof("Terminating PCF...")
	// deregister with NRF
	problemDetails, err := consumer.SendDeregisterNFInstance()
	if problemDetails != nil {
		logger.InitLog.Errorf("Deregister NF instance Failed Problem[%+v]", problemDetails)
	} else if err != nil {
		logger.InitLog.Errorf("Deregister NF instance Error[%+v]", err)
	} else {
		logger.InitLog.Infof("Deregister from NRF successfully")
	}
	logger.InitLog.Infof("PCF terminated")
}

func (pcf *PCF) registerNF() {

	for {
		//wait till Config pod updates config
		if msg := <-ConfigPodTrigger; msg {
			initLog.Infof("Config update trigger %v received in PCF App", msg)
			self := context.PCF_Self()
			profile, err := consumer.BuildNFInstance(self)
			if err != nil {
				initLog.Error("Build PCF Profile Error")
			}

			//Indefinite attempt to register until success
			_, self.NfId, err = consumer.SendRegisterNFInstance(self.NrfUri, self.NfId, profile)
			if err != nil {
				initLog.Errorf("PCF register to NRF Error[%s]", err.Error())
			} else {
				//NRF Registration Successful, Trigger for UDR Discovery
				pcf.discoverUdr()
			}
		}
	}

}

func (pcf *PCF) discoverUdr() {
	self := context.PCF_Self()
	param := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{
		ServiceNames: optional.NewInterface([]models.ServiceName{models.ServiceName_NUDR_DR}),
	}
	if resp, err := consumer.SendSearchNFInstances(self.NrfUri, models.NfType_UDR, models.NfType_PCF, param); err != nil {
		initLog.Errorln(err)
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

func getSessionRule(devGroup *protos.DeviceGroup) (sessionRule *models.SessionRule) {
	sessionRule = &models.SessionRule{}
	qos := devGroup.IpDomainDetails.UeDnnQos
	if qos.TrafficClass != nil {
		sessionRule.AuthDefQos = &models.AuthorizedDefaultQos{
			Var5qi: qos.TrafficClass.Qci,
			Arp:    &models.Arp{PriorityLevel: qos.TrafficClass.Arp},
			//PriorityLevel:
		}
	}
	sessionRule.AuthSessAmbr = &models.Ambr{
		Uplink:   strconv.FormatInt(qos.DnnMbrUplink/1000, 10) + " Kbps",
		Downlink: strconv.FormatInt(qos.DnnMbrDownlink/1000, 10) + " Kbps",
	}
	return sessionRule
}

func getPccRules(slice *protos.NetworkSlice, sessionRule *models.SessionRule) (pccPolicy context.PccPolicy) {
	if slice.AppFilters == nil || slice.AppFilters.PccRuleBase == nil {
		logger.GrpcLog.Warnf("PccRules not exist in slice: %v", slice.Name)
		return
	}
	pccPolicy.IdGenerator = idgenerator.NewGenerator(1, math.MaxInt64)
	for _, pccrule := range slice.AppFilters.PccRuleBase {
		id, _ := pccPolicy.IdGenerator.Allocate()
		var rule models.PccRule
		var qos models.QosData
		rule.PccRuleId = strconv.FormatInt(int64(id), 10)
		rule.Precedence = pccrule.Priority
		if pccrule.Qos != nil {
			qos.QosId = strconv.FormatInt(id, 10)
			qos.Var5qi = pccrule.Qos.Var5Qi
			if pccrule.Qos.MaxbrUl != 0 {
				qos.MaxbrUl = strconv.FormatInt(int64(pccrule.Qos.MaxbrUl/1000), 10)
				qos.MaxbrUl = qos.MaxbrUl + " Kbps"
			}
			if pccrule.Qos.MaxbrDl != 0 {
				qos.MaxbrDl = strconv.FormatInt(int64(pccrule.Qos.MaxbrDl/1000), 10)
				qos.MaxbrDl = qos.MaxbrDl + " Kbps"
			}
			if pccrule.Qos.GbrUl != 0 {
				qos.GbrUl = strconv.FormatInt(int64(pccrule.Qos.GbrUl/1000), 10)
				qos.GbrUl = qos.GbrUl + " Kbps"
			}
			if pccrule.Qos.GbrDl != 0 {
				qos.GbrDl = strconv.FormatInt(int64(pccrule.Qos.GbrDl/1000), 10)
				qos.GbrDl = qos.GbrDl + " Kbps"
			}
			if pccrule.Qos.Arp != nil {
				qos.Arp = &models.Arp{PriorityLevel: pccrule.Qos.Arp.PL}
				if pccrule.Qos.Arp.PC == protos.PccArpPc_NOT_PREEMPT {
					qos.Arp.PreemptCap = models.PreemptionCapability_NOT_PREEMPT
				} else if pccrule.Qos.Arp.PC == protos.PccArpPc_MAY_PREEMPT {
					qos.Arp.PreemptCap = models.PreemptionCapability_MAY_PREEMPT
				}
				if pccrule.Qos.Arp.PV == protos.PccArpPv_NOT_PREEMPTABLE {
					qos.Arp.PreemptVuln = models.PreemptionVulnerability_NOT_PREEMPTABLE
				} else if pccrule.Qos.Arp.PV == protos.PccArpPv_PREEMPTABLE {
					qos.Arp.PreemptVuln = models.PreemptionVulnerability_PREEMPTABLE
				}
			}
			if pccrule.Qos.MaxbrUl == 0 && pccrule.Qos.MaxbrDl == 0 && pccrule.Qos.GbrUl == 0 && pccrule.Qos.GbrDl == 0 {
				//getting from sessionrule
				qos.MaxbrUl = sessionRule.AuthSessAmbr.Uplink
				qos.MaxbrDl = sessionRule.AuthSessAmbr.Downlink
				qos.DefQosFlowIndication = true
			}
			rule.RefQosData = append(rule.RefQosData, qos.QosId)
			if pccPolicy.QosDecs == nil {
				pccPolicy.QosDecs = make(map[string]*models.QosData)
			}
			pccPolicy.QosDecs[qos.QosId] = &qos
		}
		for _, pflow := range pccrule.FlowInfos {
			var flow models.FlowInformation
			flow.FlowDescription = pflow.FlowDesc
			//flow.TosTrafficClass = pflow.TosTrafficClass
			id, _ := pccPolicy.IdGenerator.Allocate()
			flow.PackFiltId = strconv.FormatInt(id, 10)

			if pflow.FlowDir == protos.PccFlowDirection_DOWNLINK {
				flow.FlowDirection = models.FlowDirectionRm_DOWNLINK
			} else if pflow.FlowDir == protos.PccFlowDirection_UPLINK {
				flow.FlowDirection = models.FlowDirectionRm_UPLINK
			} else if pflow.FlowDir == protos.PccFlowDirection_BIDIRECTIONAL {
				flow.FlowDirection = models.FlowDirectionRm_BIDIRECTIONAL
			} else if pflow.FlowDir == protos.PccFlowDirection_UNSPECIFIED {
				flow.FlowDirection = models.FlowDirectionRm_UNSPECIFIED
			}
			//traffic control info set based on flow at present
			var tcData models.TrafficControlData
			tcData.TcId = "TcId-" + pccrule.RuleId

			if pflow.FlowStatus == protos.PccFlowStatus_ENABLED {
				tcData.FlowStatus = models.FlowStatus_ENABLED
			} else if pflow.FlowStatus == protos.PccFlowStatus_DISABLED {
				tcData.FlowStatus = models.FlowStatus_DISABLED
			}
			rule.RefTcData = append(rule.RefTcData, tcData.TcId)
			if pccPolicy.TraffContDecs == nil {
				pccPolicy.TraffContDecs = make(map[string]*models.TrafficControlData)
			}
			pccPolicy.TraffContDecs[tcData.TcId] = &tcData

			rule.FlowInfos = append(rule.FlowInfos, flow)
		}
		if pccPolicy.PccRules == nil {
			pccPolicy.PccRules = make(map[string]*models.PccRule)
		}
		pccPolicy.PccRules[pccrule.RuleId] = &rule
	}

	return
}

func UpdatePcfSubsriberPolicyData(slice *protos.NetworkSlice) {
	self := context.PCF_Self()
	sliceid := slice.Nssai.Sst + slice.Nssai.Sd
	switch slice.OperationType {
	case protos.OpType_SLICE_ADD:
		logger.GrpcLog.Infof("Received Slice with OperationType: Add from ConfigPod")
		for _, devgroup := range slice.DeviceGroup {
			var sessionrule *models.SessionRule
			var dnn string
			if devgroup.IpDomainDetails != nil && devgroup.IpDomainDetails.UeDnnQos != nil {
				dnn = devgroup.IpDomainDetails.DnnName
				sessionrule = getSessionRule(devgroup)
			}
			for _, imsi := range devgroup.Imsi {
				self.PcfSubscriberPolicyData[imsi] = &context.PcfSubscriberPolicyData{}
				policyData := self.PcfSubscriberPolicyData[imsi]
				policyData.PccPolicy = make(map[string]*context.PccPolicy)
				policyData.PccPolicy[sliceid] = &context.PccPolicy{make(map[string]*models.PccRule),
					make(map[string]*models.QosData), make(map[string]*models.TrafficControlData),
					make(map[string]*context.SessionPolicy), nil}
				policyData.PccPolicy[sliceid].SessionPolicy[dnn] = &context.SessionPolicy{make(map[string]*models.SessionRule), idgenerator.NewGenerator(1, math.MaxInt16)}
				id, _ := policyData.PccPolicy[sliceid].SessionPolicy[dnn].SessionRuleIdGenerator.Allocate()
				//tcid, _ := policyData.PccPolicy[sliceid].TcIdGenerator.Allocate()
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
				self.DisplayPcfSubscriberPolicyData(imsi)
			}
		}
	case protos.OpType_SLICE_UPDATE:
		logger.GrpcLog.Infof("Received Slice with OperationType: Update from ConfigPod")
		for _, devgroup := range slice.DeviceGroup {
			var sessionrule *models.SessionRule
			var dnn string
			if devgroup.IpDomainDetails == nil || devgroup.IpDomainDetails.UeDnnQos == nil {
				logger.GrpcLog.Warnf("ip details or qos details in ipdomain not exist for device group: %v", devgroup.Name)
				continue
			}

			dnn = devgroup.IpDomainDetails.DnnName
			sessionrule = getSessionRule(devgroup)

			for _, imsi := range slice.AddUpdatedImsis {
				if ImsiExistInDeviceGroup(devgroup, imsi) {
					policyData, _ := self.PcfSubscriberPolicyData[imsi]
					// TODO policy exists for this imsi, then take difference and notify the subscriber
					self.PcfSubscriberPolicyData[imsi] = &context.PcfSubscriberPolicyData{}
					policyData = self.PcfSubscriberPolicyData[imsi]
					policyData.PccPolicy = make(map[string]*context.PccPolicy)
					policyData.PccPolicy[sliceid] = &context.PccPolicy{make(map[string]*models.PccRule),
						make(map[string]*models.QosData), make(map[string]*models.TrafficControlData),
						make(map[string]*context.SessionPolicy), nil}
					policyData.PccPolicy[sliceid].SessionPolicy[dnn] = &context.SessionPolicy{make(map[string]*models.SessionRule), idgenerator.NewGenerator(1, math.MaxInt16)}

					//Added session rules
					id, _ := policyData.PccPolicy[sliceid].SessionPolicy[dnn].SessionRuleIdGenerator.Allocate()
					sessionrule.SessRuleId = dnn + strconv.Itoa(int(id))
					policyData.PccPolicy[sliceid].SessionPolicy[dnn].SessionRules[sessionrule.SessRuleId] = sessionrule
					//Added pcc rules
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
				}
				self.DisplayPcfSubscriberPolicyData(imsi)
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
			//sessionrules, pccrules if exist in slice, implicitly deletes all sessionrules, pccrules for this sliceid
			logger.GrpcLog.Infof("slice: %v deleted from SubscriberPolicyData", sliceid)
			delete(policyData.PccPolicy, sliceid)
			if len(policyData.PccPolicy) == 0 {
				logger.GrpcLog.Infof("Subscriber: %v deleted from PcfSubscriberPolicyData map", imsi)
				delete(self.PcfSubscriberPolicyData, imsi)
			}
		}

	case protos.OpType_SLICE_DELETE:
		logger.GrpcLog.Infof("Received Slice with OperationType: Update from ConfigPod")
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
			logger.GrpcLog.Infof("slice: %v deleted from SubscriberPolicyData", sliceid)
			delete(policyData.PccPolicy, sliceid)
			if len(policyData.PccPolicy) == 0 {
				logger.GrpcLog.Infof("Subscriber: %v deleted from PcfSubscriberPolicyData map", imsi)
				delete(self.PcfSubscriberPolicyData, imsi)
			}
		}

	}
}
func (pcf *PCF) updateConfig(commChannel chan *protos.NetworkSliceResponse) bool {
	var minConfig bool
	pcfContext := context.PCF_Self()
	for rsp := range commChannel {
		logger.GrpcLog.Infoln("Received updateConfig in the pcf app : ", rsp)
		for _, ns := range rsp.NetworkSlice {
			logger.GrpcLog.Infoln("Network Slice Name ", ns.Name)

			//Update Qos Info
			//Update/Create/Delete PcfSubscriberPolicyData
			UpdatePcfSubsriberPolicyData(ns)
			/*if ns.Qos != nil {
				if qi, err := strconv.Atoi(ns.Qos.TrafficClass); err != nil {
					logger.GrpcLog.Infoln("invalid traffic class: ", ns.Qos.TrafficClass)
				} else {
					pcfContext.DefQosMap[ns.Nssai.Sst+ns.Nssai.Sd] = models.SubscribedDefaultQos{Var5qi: int32(qi)}
				}

				if ns.Qos.Uplink > 0 && ns.Qos.Downlink > 0 {
					ulAmbr := strconv.Itoa(int(ns.Qos.Uplink)) + " Mbps"
					dlAmbr := strconv.Itoa(int(ns.Qos.Downlink)) + " Mbps"
					pcfContext.AmbrMap[ns.Nssai.Sst+ns.Nssai.Sd] = models.Ambr{Uplink: ulAmbr, Downlink: dlAmbr}
				}
			}*/

			if ns.Site != nil {
				temp := factory.PlmnSupportItem{}
				var found bool = false
				logger.GrpcLog.Infoln("Network Slice has site name present ")
				site := ns.Site
				logger.GrpcLog.Infoln("Site name ", site.SiteName)
				if site.Plmn != nil {
					temp.PlmnId.Mcc = site.Plmn.Mcc
					temp.PlmnId.Mnc = site.Plmn.Mnc
					logger.GrpcLog.Infoln("Plmn mcc ", site.Plmn.Mcc)
					for _, item := range pcfContext.PlmnList {
						if item.PlmnId.Mcc == temp.PlmnId.Mcc && item.PlmnId.Mnc == temp.PlmnId.Mnc {
							found = true
							break
						}
					}
					if !found {
						pcfContext.PlmnList = append(pcfContext.PlmnList, temp)
						logger.GrpcLog.Infoln("Plmn added in the context", pcfContext.PlmnList)
					}
				} else {
					logger.GrpcLog.Infoln("Plmn not present in the message ")
				}
			}
		}
		if !minConfig {
			// first slice Created
			if len(pcfContext.PlmnList) > 0 {
				minConfig = true
				ConfigPodTrigger <- true
				logger.GrpcLog.Infoln("Send config trigger to main routine first time config")
			}
		} else {
			// all slices deleted
			if len(pcfContext.PlmnList) == 0 {
				minConfig = false
				ConfigPodTrigger <- false
				logger.GrpcLog.Infoln("Send config trigger to main routine config deleted")
			} else {
				ConfigPodTrigger <- true
				logger.GrpcLog.Infoln("Send config trigger to main routine config updated")
			}
		}
	}
	return true
}
