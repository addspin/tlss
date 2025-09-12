package check

import (
	"time"

	"github.com/spf13/viper"
)

type Monitor struct {
	RecreateCerts         time.Time
	CheckValidCerts       time.Time
	CheckTCP              time.Time
	RecreateCertStatus    bool
	CheckValidCertsStatus bool
	CheckTCPStatus        bool
}

func (m *Monitor) CheckMonitor() {

	recreateCertsInterval := time.Duration(viper.GetInt("recreateCerts.time")) * time.Second
	recreateCertsTimeNow := time.Now()
	recreateDuration := recreateCertsTimeNow.Sub(m.RecreateCerts)
	if recreateDuration > recreateCertsInterval {
		m.RecreateCertStatus = true
	} else {
		m.RecreateCertStatus = false
	}
}
