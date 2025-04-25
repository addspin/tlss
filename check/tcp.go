package check

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/addspin/tlss/models"
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
		log.Printf("Error open database: %v", err)
		return
	}
	fmt.Println("Connected to database: ", database)
	defer db.Close()

	var checkServerList bool
	for range ticker.C {
		// проверяем, есть хотя бы один сервер в базе данных?
		err = db.Get(&checkServerList, "SELECT EXISTS(SELECT 1 FROM server)")
		if err != nil {
			log.Printf("Error checking server list: %v", err)
			continue
		}
		// если нет, пишем что в базе нет серверов
		if !checkServerList {
			log.Println("No servers in database")
			continue
		}
		// извлекаем список северов из базы данных
		serverList := []models.Server{}
		err = db.Select(&serverList, "SELECT hostname, port FROM server")
		if err != nil {
			log.Printf("Error selecting servers: %v", err)
			continue
		}
		// проходимся по списку серверов и проверяем доступность
		for _, server := range serverList {
			conn, err := net.Dial("tcp", server.Hostname+":"+server.Port)
			if err != nil {
				s.ExitCodeTcp = false // port is not available
				// log.Println("TCP port is not available:", server.Hostname+":"+server.Port)
				log.Printf("TCP port is not available: %s:%s, error: %v", server.Hostname, server.Port, err)
				_, err = db.Exec("UPDATE server SET server_status = ? WHERE hostname = ? AND port = ?", "offline", server.Hostname, server.Port)
				if err != nil {
					log.Printf("Error updating server status: %v", err)
					continue
				}
			} else {
				s.ExitCodeTcp = true // port is available
				// log.Println("TCP port is available:", server.Hostname+":"+server.Port)
				log.Printf("TCP port is available: %s:%s", server.Hostname, server.Port)
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
