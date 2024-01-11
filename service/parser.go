package service

import (
	"github.com/kardianos/service"
	"github.com/metacubex/mihomo/log"
	"os"
)

// Parser parses the command line arguments and runs as a service.
// 如果需要程序退出（包括对服务的操作：install、uninstall、start、stop）则返回真
// 不需要退出程序（run、noninteractive(服务中启动)）返回假
// 其他命令则以 cmd == "run" 处理
// 注意：本函数需要处理的非常快（毫秒级别）
// 代码以空间换时间
func Parser(cmd string, runFunc func()) {
	status, err := Init(runFunc)

	switch cmd {
	case "install":
		err = SysService.Install()

	case "uninstall":
		err = SysService.Uninstall()

	case "start":
		if status != service.StatusRunning {
			err = SysService.Start()
		}

	case "stop":
		if status != service.StatusStopped {
			err = SysService.Stop()
		}

	case "restart":
		err = SysService.Restart()

	case "status":
		if err != nil {
			log.Errorln("Failed to get service status: %s", err)
			return
		}
		log.Infoln("Service status:%d (0:Unknown 1:Running 2:Stopped)", status)

	case "noninteractive":
		// 在服务中启动
		Noninteractive = true
		log.Infoln("Running in service.")
		err = SysService.Run()
		if err != nil {
			log.Errorln("Failed to run service: %s", err)
		}
	default:
		// 直接运行
		log.Infoln("Running in terminal.")
		err = SysService.Run()
		if err != nil {
			log.Errorln("Failed to run service: %s", err)
		}
	}

	actionLog(cmd, err)

	if err != nil {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}
