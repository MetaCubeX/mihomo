package cmd

import (
	"github.com/metacubex/mihomo/cmd/flags"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"

	"github.com/spf13/cobra"
)

var commandRun = &cobra.Command{
	Use:   "run",
	Short: "Run Mihomo",
	Run:   runApp,
}

func runApp(cmd *cobra.Command, args []string) {
	err := run()
	if err != nil {
		log.Errorln(err.Error())
	}
}

func init() {
	RootCmd.AddCommand(commandRun)
}

func run() error {
	setupMaxProcs()

	if flags.Version {
		printVersion()
		return nil
	}

	err := testConfig()
	if err != nil {
		return err
	}

	if flags.TestConfig {
		return nil
	}

	options := parseOptions()
	if err := hub.Parse(options...); err != nil {
		log.Fatalln("Parse config error: %s", err.Error())
	}

	if C.GeoAutoUpdate {
		startGeoUpdater()
	}

	defer executor.Shutdown()

	handleSignals()
	return nil
}
