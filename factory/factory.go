/*
 * PCF Configuration Factory
 */

package factory

import (
	"fmt"
	"reflect"
	"io/ioutil"

	"gopkg.in/yaml.v2"

	"github.com/free5gc/pcf/logger"
)

var PcfConfig Config

// TODO: Support configuration update from REST api
func InitConfigFactory(f string) error {
	if content, err := ioutil.ReadFile(f); err != nil {
		return err
	} else {
		PcfConfig = Config{}

		if yamlErr := yaml.Unmarshal(content, &PcfConfig); yamlErr != nil {
			return yamlErr
		}
	}

	return nil
}
func UpdatePcfConfig(f string) error {
	if content, err := ioutil.ReadFile(f); err != nil {
		return err
	} else {
		var pcfConfig Config

		if yamlErr := yaml.Unmarshal(content, &pcfConfig); yamlErr != nil {
			return yamlErr
		}
		//Checking which config has been changed
		if reflect.DeepEqual(PcfConfig.Configuration.PcfName, pcfConfig.Configuration.PcfName) == false {
			logger.CfgLog.Infoln("updated PCF Name ", pcfConfig.Configuration.PcfName)
		} 
		if reflect.DeepEqual(PcfConfig.Configuration.Sbi, pcfConfig.Configuration.Sbi) == false {
			logger.CfgLog.Infoln("updated Sbi ", pcfConfig.Configuration.Sbi)
		} 
		if reflect.DeepEqual(PcfConfig.Configuration.TimeFormat, pcfConfig.Configuration.TimeFormat) == false {
			logger.CfgLog.Infoln("updated TIme Format ", pcfConfig.Configuration.TimeFormat)
		} 
		if reflect.DeepEqual(PcfConfig.Configuration.DefaultBdtRefId, pcfConfig.Configuration.DefaultBdtRefId) == false {
			logger.CfgLog.Infoln("updated DefaultBdtRefId ", pcfConfig.Configuration.DefaultBdtRefId)
		} 
		if reflect.DeepEqual(PcfConfig.Configuration.NrfUri, pcfConfig.Configuration.NrfUri) == false {
			logger.CfgLog.Infoln("updated NrfUri ", pcfConfig.Configuration.NrfUri)
		} 
		if reflect.DeepEqual(PcfConfig.Configuration.ServiceList, pcfConfig.Configuration.ServiceList) == false {
			logger.CfgLog.Infoln("updated ServiceList ", pcfConfig.Configuration.ServiceList)
		} 
		if reflect.DeepEqual(PcfConfig.Configuration.Mongodb, pcfConfig.Configuration.Mongodb) == false {
			logger.CfgLog.Infoln("updated Mongodb ", pcfConfig.Configuration.PcfName)
		} 
		
		PcfConfig = pcfConfig
	}

	return nil
}
func CheckConfigVersion() error {
	currentVersion := PcfConfig.GetVersion()

	if currentVersion != PCF_EXPECTED_CONFIG_VERSION {
		return fmt.Errorf("config version is [%s], but expected is [%s].",
			currentVersion, PCF_EXPECTED_CONFIG_VERSION)
	}

	logger.CfgLog.Infof("config version [%s]", currentVersion)

	return nil
}
