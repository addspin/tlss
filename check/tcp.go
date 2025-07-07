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
	log.Println("TCP check started")
	defer ticker.Stop()
	s.MutexTcp.Lock()
	defer s.MutexTcp.Unlock()
	//---------------------------------------Database inicialization
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Printf("Ошибка открытия базы данных: %v", err)
		return
	}
	fmt.Println("Подключено к базе данных: ", database)
	defer db.Close()

	var checkServerList bool
	for range ticker.C {
		// проверяем, есть хотя бы один сервер в базе данных?
		err = db.Get(&checkServerList, "SELECT EXISTS(SELECT 1 FROM server)")
		if err != nil {
			log.Printf("Ошибка проверки списка серверов: %v", err)
			continue
		}
		// если нет, пишем что в базе нет серверов
		if !checkServerList {
			log.Println("В базе данных нет серверов")
			continue
		}
		// извлекаем список северов из базы данных
		serverList := []models.Server{}
		err = db.Select(&serverList, "SELECT hostname, port FROM server")
		if err != nil {
			log.Printf("Ошибка выбора серверов: %v", err)
			continue
		}
		// проходимся по списку серверов и проверяем доступность
		testData := utils.NewTestData()
		port, err := testData.TestString(serverList[0].Port)
		if err != nil {
			log.Printf("Ошибка преобразования порта: %v", err)
			continue
		}
		for _, server := range serverList {
			conn, err := net.Dial("tcp", server.Hostname+":"+port)
			if err != nil {
				s.ExitCodeTcp = false // port is not available
				// log.Println("TCP port is not available:", server.Hostname+":"+server.Port)
				log.Printf("TCP порт не доступен: %s:%d, ошибка: %v", server.Hostname, server.Port, err)
				_, err = db.Exec("UPDATE server SET server_status = ? WHERE hostname = ? AND port = ?", "offline", server.Hostname, server.Port)
				if err != nil {
					log.Printf("Ошибка обновления статуса сервера: %v", err)
					continue
				}
			} else {
				s.ExitCodeTcp = true // port is available
				// log.Println("TCP port is available:", server.Hostname+":"+server.Port)
				log.Printf("TCP порт доступен: %s:%d", server.Hostname, server.Port)
				// меняем значение в базе данных c offline на online
				_, err = db.Exec("UPDATE server SET server_status = ? WHERE hostname = ? AND port = ?", "online", server.Hostname, server.Port)
				if err != nil {
					log.Printf("Error updating server status: %v", err)
				}
				conn.Close()
			}
		}
	}
}
