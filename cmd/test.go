package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/metacubex/mihomo/cmd/flags"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"

	"github.com/spf13/cobra"
)

var commandTest = &cobra.Command{
	Use:   "test",
	Short: "Test configuration and exit",
	Run:   cmdTestConfig,
	Args:  cobra.NoArgs,
}

func init() {
	RootCmd.AddCommand(commandTest)
}

func cmdTestConfig(cmd *cobra.Command, args []string) {
	flags.TestConfig = true
	err := testConfig()
	if err != nil {
		log.Errorln(err.Error())
	}
}

func testConfig() error {

	if flags.HomeDir != "" {
		flags.HomeDir = resolvePath(flags.HomeDir)
		C.SetHomeDir(flags.HomeDir)
	}

	if flags.ConfigFile != "" {
		flags.ConfigFile = resolvePath(flags.ConfigFile)
		C.SetConfig(flags.ConfigFile)
	} else {
		flags.ConfigFile = filepath.Join(C.Path.HomeDir(), C.Path.Config())
		C.SetConfig(C.Path.Config())
	}

	if flags.GeodataMode {
		C.GeodataMode = true
	}

	if err := config.Init(C.Path.HomeDir()); err != nil {
		log.Fatalln("Initial configuration directory error: %s", err.Error())
		return err
	}

	if flags.TestConfig {
		if _, err := executor.Parse(); err != nil {
			log.Errorln(err.Error())
			fmt.Printf("configuration file %s test failed\n", C.Path.Config())
			os.Exit(1)
		}
		fmt.Printf("configuration file %s test is successful\n", C.Path.Config())
		return nil
	}

	return nil
}
