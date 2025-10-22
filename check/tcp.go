package check

import (
	"log/slog"
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

	slog.Info("TCP checker: Server availability check started")
	//---------------------------------------Database inicialization
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("TCP checker: Database open error", "error", err)
		return
	}
	defer db.Close()

	var checkServerList bool
	// проверяем, есть хотя бы один сервер в базе данных?
	err = db.Get(&checkServerList, "SELECT EXISTS(SELECT 1 FROM server)")
	if err != nil {
		slog.Error("TCP checker: Server list check error", "error", err)
		return
	}
	// если нет, пишем что в базе нет серверов
	if !checkServerList {
		slog.Info("TCP checker: No servers in database")
		Monitors.CheckTCP = time.Now()
		return
	}
	// извлекаем список северов из базы данных
	serverList := []models.Server{}
	err = db.Select(&serverList, "SELECT hostname, port FROM server WHERE port IS NOT NULL")
	if err != nil {
		slog.Error("TCP checker: Error retrieving servers from database", "error", err)
		return
	}
	// Проверка на наличие сервера в базе данных
	if len(serverList) == 0 {
		slog.Info("TCP checker: No servers to check in database")
	} else {
		// проходимся по списку серверов и проверяем доступность
		testData := utils.NewTestData()
		for _, server := range serverList {
			port, err := testData.TestString(server.Port)
			if err != nil {
				slog.Error("TCP checker: Port conversion error", "hostname", server.Hostname, "error", err)
				continue
			}
			conn, err := net.Dial("tcp", server.Hostname+":"+port)
			if err != nil {
				s.ExitCodeTcp = false // port is not available
				// slog.Info("TCP port is not available", "hostname", server.Hostname, "port", server.Port)
				slog.Warn("TCP checker: Port is not available", "hostname", server.Hostname, "port", server.Port, "error", err)
				_, err = db.Exec("UPDATE server SET server_status = ? WHERE hostname = ? AND port = ?", "offline", server.Hostname, server.Port)
				if err != nil {
					slog.Error("TCP checker: Server status update error", "error", err)
					continue
				}
			} else {
				s.ExitCodeTcp = true // port is available
				// slog.Info("TCP port is available", "hostname", server.Hostname, "port", server.Port)
				slog.Info("TCP checker: Port is available", "hostname", server.Hostname, "port", server.Port)
				// меняем значение в базе данных c offline на online
				_, err = db.Exec("UPDATE server SET server_status = ? WHERE hostname = ? AND port = ?", "online", server.Hostname, server.Port)
				if err != nil {
					slog.Error("TCP checker: Server status update error", "error", err)
				}
				conn.Close()
			}
		}
	}
	// Обновляем время последней проверки ВСЕГДА, даже если серверов нет
	Monitors.CheckTCP = time.Now()
}
