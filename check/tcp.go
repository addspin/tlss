package check

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/addspin/tlss/utils"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

type StatusCodeTcp struct {
	ExitCodeTcp bool
	MyState     string
	MutexTcp    sync.Mutex
}

func (s *StatusCodeTcp) TCPPortAvailable(timeTicker time.Duration) {
	// Выполняем проверку сразу при запуске
	s.checkPort()

	// Затем запускаем периодическую проверку
	ticker := time.NewTicker(timeTicker)
	defer ticker.Stop()

	for range ticker.C {
		s.checkPort()
	}
}

func (s *StatusCodeTcp) checkPort() {
	s.MutexTcp.Lock()
	defer s.MutexTcp.Unlock()

	log.Println("TCP checker: Проверка доступности серверов началась")
	//---------------------------------------Database inicialization
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Printf("TCP checker: Ошибка открытия базы данных: %v", err)
		return
	}
	defer db.Close()

	var checkServerList bool
	// проверяем, есть хотя бы один сервер в базе данных?
	err = db.Get(&checkServerList, "SELECT EXISTS(SELECT 1 FROM server)")
	if err != nil {
		log.Printf("TCP checker: Ошибка проверки списка серверов: %v", err)
		return
	}
	// если нет, пишем что в базе нет серверов
	if !checkServerList {
		log.Println("TCP checker: В базе данных нет ни одного сервера")
		Monitors.CheckTCP = time.Now()
		return
	}
	// извлекаем список северов из базы данных
	serverList := []models.Server{}
	err = db.Select(&serverList, "SELECT hostname, port FROM server WHERE port IS NOT NULL")
	if err != nil {
		log.Printf("TCP checker: Ошибка извлечения серверов из базы данных: %v", err)
		return
	}
	// Проверка на наличие сервера в базе данных
	if len(serverList) == 0 {
		log.Println("TCP checker: В базе данных нет серверов для проверки")
	} else {
		// проходимся по списку серверов и проверяем доступность
		testData := utils.NewTestData()
		for _, server := range serverList {
			port, err := testData.TestString(server.Port)
			if err != nil {
				log.Printf("TCP checker: Ошибка преобразования порта для %s: %v", server.Hostname, err)
				continue
			}
			conn, err := net.Dial("tcp", server.Hostname+":"+port)
			if err != nil {
				s.ExitCodeTcp = false // port is not available
				// log.Println("TCP port is not available:", server.Hostname+":"+server.Port)
				log.Printf("TCP checker: порт не доступен: %s:%d, ошибка: %v", server.Hostname, server.Port, err)
				_, err = db.Exec("UPDATE server SET server_status = ? WHERE hostname = ? AND port = ?", "offline", server.Hostname, server.Port)
				if err != nil {
					log.Printf("TCP checker: Ошибка обновления статуса сервера: %v", err)
					continue
				}
			} else {
				s.ExitCodeTcp = true // port is available
				// log.Println("TCP port is available:", server.Hostname+":"+server.Port)
				log.Printf("TCP checker: порт доступен: %s:%d", server.Hostname, server.Port)
				// меняем значение в базе данных c offline на online
				_, err = db.Exec("UPDATE server SET server_status = ? WHERE hostname = ? AND port = ?", "online", server.Hostname, server.Port)
				if err != nil {
					log.Printf("TCP checker: Ошибка обновления статуса сервера: %v", err)
				}
				conn.Close()
			}
		}
	}
	// Обновляем время последней проверки ВСЕГДА, даже если серверов нет
	Monitors.CheckTCP = time.Now()
}
