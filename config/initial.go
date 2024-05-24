package config

import (
	"fmt"
	"github.com/go-co-op/gocron"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel/statistic"
	"os"
	P "path"
	"time"
)

// Init prepare necessary files
func Init(dir string) error {
	// initial homedir
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o777); err != nil {
			return fmt.Errorf("can't create config directory %s: %s", dir, err.Error())
		}
	}

	// initial config.yaml
	if _, err := os.Stat(C.Path.Config()); os.IsNotExist(err) {
		log.Infoln("Can't find config, create a initial config file")
		f, err := os.OpenFile(C.Path.Config(), os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("can't create file %s: %s", C.Path.Config(), err.Error())
		}
		f.Write([]byte(`mixed-port: 7890`))
		f.Close()
	}

	if _, err := os.Stat(C.Path.StatisticPath()); os.IsNotExist(err) {
		if err = os.Mkdir(C.Path.StatisticPath(), os.ModePerm); err != nil {
			log.Errorln(err.Error())
		}
	}

	statistic.RestoreChannelsData(CurrentMonthStatisticFileName())
	s := gocron.NewScheduler(time.Local)
	s.Every(10).Minutes().Do(func() {
		ts := time.Now().AddDate(0, 0, -1)
		fileName := P.Join(C.Path.StatisticPath(), ts.Format("200601")+"-statistic.json")
		statistic.SaveChannelsData(fileName)
		if fileName != CurrentMonthStatisticFileName() {
			for _, v := range statistic.ChannelManager {
				v.ResetStatistic()
			}
		}
	})
	s.StartAsync()

	return nil
}
func CurrentMonthStatisticFileName() string {
	return P.Join(C.Path.StatisticPath(), time.Now().Format("200601")+"-statistic.json")
}
