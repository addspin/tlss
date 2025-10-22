package check

import (
	"log/slog"
	"sync"
	"time"

	"github.com/addspin/tlss/utils"
	"github.com/spf13/viper"
)

type Mon struct {
	RecreateCerts         time.Time
	CheckValidCerts       time.Time
	CheckTCP              time.Time
	RecreateCertStatus    bool
	CheckValidCertsStatus bool
	CheckTCPStatus        bool
	MutexMonitor          sync.Mutex
}

var Monitors = Mon{}

func Monitore(TCPInterval, RecreateCertsInterval, CheckValidCertsInterval time.Duration) {
	slog.Info("CheckMonitor: Starting monitoring module")

	// Инициализируем время при запуске мониторинга
	now := time.Now()
	Monitors.CheckTCP = now
	Monitors.RecreateCerts = now
	Monitors.CheckValidCerts = now

	// Выполняем проверки сразу при запуске
	checkMonitorTCP()
	checkMonitorRecreateCerts()
	checkMonitorCheckValidCerts()

	// Создаём тикеры
	tickerTCP := time.NewTicker(TCPInterval)
	defer tickerTCP.Stop()

	tickerRecreateCerts := time.NewTicker(RecreateCertsInterval)
	defer tickerRecreateCerts.Stop()

	tickerCheckValidCerts := time.NewTicker(CheckValidCertsInterval)
	defer tickerCheckValidCerts.Stop()

	// Используем select для одновременного мониторинга всех каналов
	for {
		select {
		case <-tickerTCP.C:
			checkMonitorTCP()
		case <-tickerRecreateCerts.C:
			checkMonitorRecreateCerts()
		case <-tickerCheckValidCerts.C:
			checkMonitorCheckValidCerts()
		}
	}
}

func checkMonitorTCP() {
	Monitors.MutexMonitor.Lock()
	defer Monitors.MutexMonitor.Unlock()
	// интервал TCP чекера (не монитора!)
	checkTCPInterval := utils.SelectTime(viper.GetString("checkServer.unit"), viper.GetInt("checkServer.checkServerInterval"))
	// время сейчас
	checkTCPTimeNow := time.Now()
	// время разницу между временем сейчас и временем последнего пересоздания сертификатов
	checkTCPDuration := checkTCPTimeNow.Sub(Monitors.CheckTCP)
	// slog.Info("CheckMonitor: Time difference", "duration", checkTCPDuration)
	// если время разницы больше интервала чекера + небольшой запас, то устанавливаем статус false
	// добавляем 50% запаса времени для учета задержек выполнения
	if checkTCPDuration > checkTCPInterval+(checkTCPInterval/2) {
		Monitors.CheckTCPStatus = false // чекер не работает
		slog.Warn("CheckMonitor TCP: Checker is not working")
	} else {
		Monitors.CheckTCPStatus = true // чекер работает
		slog.Info("CheckMonitor TCP: Checker is working")
	}
	slog.Info("CheckMonitor: Monitoring is running")
}

func checkMonitorRecreateCerts() {
	Monitors.MutexMonitor.Lock()
	defer Monitors.MutexMonitor.Unlock()
	recreateCertsInterval := utils.SelectTime(viper.GetString("recreateCerts.unit"), viper.GetInt("recreateCerts.recreateCertsInterval"))
	recreateCertsTimeNow := time.Now()
	recreateDuration := recreateCertsTimeNow.Sub(Monitors.RecreateCerts)
	// slog.Info("CheckMonitor RecreateCerts: Time difference", "duration", recreateDuration)
	// добавляем 50% запаса времени для учета задержек выполнения
	if recreateDuration > recreateCertsInterval+(recreateCertsInterval/2) {
		Monitors.RecreateCertStatus = false // чекер не работает
		slog.Warn("CheckMonitor RecreateCerts: Checker is not working")
	} else {
		Monitors.RecreateCertStatus = true // чекер работает
		slog.Info("CheckMonitor RecreateCerts: Checker is working")
	}
}

func checkMonitorCheckValidCerts() {
	Monitors.MutexMonitor.Lock()
	defer Monitors.MutexMonitor.Unlock()
	CheckValidCertsInterval := utils.SelectTime(viper.GetString("certsValidation.unit"), viper.GetInt("certsValidation.certsValidationInterval"))
	CheckValidCertsTimeNow := time.Now()
	CheckValidCertsDuration := CheckValidCertsTimeNow.Sub(Monitors.CheckValidCerts)
	// slog.Info("CheckMonitor CheckValidCerts: Time difference", "duration", CheckValidCertsDuration)
	// добавляем 50% запаса времени для учета задержек выполнения
	if CheckValidCertsDuration > CheckValidCertsInterval+(CheckValidCertsInterval/2) {
		Monitors.CheckValidCertsStatus = false // чекер не работает
		slog.Warn("CheckMonitor CheckValidCerts: Checker is not working")
	} else {
		Monitors.CheckValidCertsStatus = true // чекер работает
		slog.Info("CheckMonitor CheckValidCerts: Checker is working")
	}
}
