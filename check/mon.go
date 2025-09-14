package check

import (
	"log"
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
	log.Println("CheckMonitor: Запуск модуля мониторинга")

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
	// интервал заданный в конфиге
	checkTCPInterval := utils.SelectTime(viper.GetString("checkServer.unit"), viper.GetInt("checkServer.checkServerInterval"))
	// время сейчас
	checkTCPTimeNow := time.Now()
	// время разницу между временем сейчас и временем последнего пересоздания сертификатов
	checkTCPDuration := checkTCPTimeNow.Sub(Monitors.CheckTCP)
	// log.Println("CheckMonitor: Время разницы:", checkTCPDuration)
	// если время разницы больше интервала, то устанавливаем статус false
	if checkTCPDuration > checkTCPInterval {
		Monitors.CheckTCPStatus = false // чекер не работает
		log.Println("CheckMonitor TCP: Чекер не работает")
	} else {
		Monitors.CheckTCPStatus = true // чекер работает
		log.Println("CheckMonitor TCP: Чекер работает")
	}
	log.Println("CheckMonitor: Мониторинг выполняется")
}

func checkMonitorRecreateCerts() {
	Monitors.MutexMonitor.Lock()
	defer Monitors.MutexMonitor.Unlock()
	recreateCertsInterval := utils.SelectTime(viper.GetString("recreateCerts.unit"), viper.GetInt("recreateCerts.recreateCertsInterval"))
	recreateCertsTimeNow := time.Now()
	recreateDuration := recreateCertsTimeNow.Sub(Monitors.RecreateCerts)
	log.Println("CheckMonitor RecreateCerts: Время разницы:", recreateDuration)
	if recreateDuration > recreateCertsInterval {
		Monitors.RecreateCertStatus = false // чекер не работает
		log.Println("CheckMonitor RecreateCerts: Чекер не работает")
	} else {
		Monitors.RecreateCertStatus = true // чекер работает
		log.Println("CheckMonitor RecreateCerts: Чекер работает")
	}
}

func checkMonitorCheckValidCerts() {
	Monitors.MutexMonitor.Lock()
	defer Monitors.MutexMonitor.Unlock()
	CheckValidCertsInterval := utils.SelectTime(viper.GetString("certsValidation.unit"), viper.GetInt("certsValidation.certsValidationInterval"))
	CheckValidCertsTimeNow := time.Now()
	CheckValidCertsDuration := CheckValidCertsTimeNow.Sub(Monitors.CheckValidCerts)
	log.Println("CheckMonitor CheckValidCerts: Время разницы:", CheckValidCertsDuration)
	if CheckValidCertsDuration > CheckValidCertsInterval {
		Monitors.CheckValidCertsStatus = false // чекер не работает
		log.Println("CheckMonitor CheckValidCerts: Чекер не работает")
	} else {
		Monitors.CheckValidCertsStatus = true // чекер работает
		log.Println("CheckMonitor CheckValidCerts: Чекер работает")
	}
}
