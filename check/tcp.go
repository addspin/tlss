package check

import (
	"fmt"
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
	ticker := time.NewTicker(timeTicker)
	defer ticker.Stop()
	s.MutexTcp.Lock()
	defer s.MutexTcp.Unlock()
	//---------------------------------------Database inicialization
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Printf("TCP checker: Ошибка открытия базы данных: %v", err)
		return
	}
	fmt.Println("TCP checker: Подключено к базе данных: ", database)
	defer db.Close()

	var checkServerList bool
	for range ticker.C {
		log.Println("TCP checker: Проверка доступности серверов началась")
		// проверяем, есть хотя бы один сервер в базе данных?
		err = db.Get(&checkServerList, "SELECT EXISTS(SELECT 1 FROM server)")
		if err != nil {
			log.Printf("TCP checker: Ошибка проверки списка серверов: %v", err)
			Monitors.CheckTCP = time.Now()
			continue
		}
		// если нет, пишем что в базе нет серверов
		if !checkServerList {
			log.Println("TCP checker: В базе данных нет ни одного сервера")
			Monitors.CheckTCP = time.Now()
			continue
		}
		// извлекаем список северов из базы данных
		serverList := []models.Server{}
		err = db.Select(&serverList, "SELECT hostname, port FROM server WHERE port IS NOT NULL")
		if err != nil {
			log.Printf("TCP checker: Ошибка извлечения серверов из базы данных: %v", err)
			Monitors.CheckTCP = time.Now()
			continue
		}
		// Проверка на наличие сервера в базе данных
		if len(serverList) == 0 {
			log.Println("TCP checker: В базе данных нет серверов для проверки")
			Monitors.CheckTCP = time.Now()
			continue
		}
		// проходимся по списку серверов и проверяем доступность
		testData := utils.NewTestData()
		port, err := testData.TestString(serverList[0].Port)
		if err != nil {
			log.Printf("TCP checker: Ошибка преобразования порта: %v", err)
			Monitors.CheckTCP = time.Now()
			continue
		}
		for _, server := range serverList {
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
		Monitors.CheckTCP = time.Now()
	}
}
