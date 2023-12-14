package cmd

import (
	"fmt"
	"os"

	"github.com/metacubex/mihomo/cmd/flags"
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "mihomo",
	Short: "A rule-based tunnel in Go.",
	Long:  `Mihomo is a rule-based tunnel in Go. Check out the wiki page for more information: https://wiki.metacubex.one/`,
	Run:   runApp,
}

func init() {
	RootCmd.PersistentFlags().StringVarP(&flags.HomeDir, "dir", "d", os.Getenv("CLASH_HOME_DIR"), "set configuration directory")
	RootCmd.PersistentFlags().StringVarP(&flags.ConfigFile, "config", "f", os.Getenv("CLASH_CONFIG_FILE"), "specify configuration file")
	RootCmd.PersistentFlags().StringVarP(&flags.ExternalUI, "ext-ui", "", os.Getenv("CLASH_OVERRIDE_EXTERNAL_UI_DIR"), "override external ui directory")
	RootCmd.PersistentFlags().StringVarP(&flags.ExternalController, "ext-ctl", "", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER"), "override external controller address")
	RootCmd.PersistentFlags().StringVarP(&flags.Secret, "secret", "", os.Getenv("CLASH_OVERRIDE_SECRET"), "override secret for RESTful API")
	RootCmd.PersistentFlags().BoolVarP(&flags.GeodataMode, "geodata", "m", false, "set geodata mode")
	RootCmd.PersistentFlags().BoolVarP(&flags.Version, "version", "v", false, "show current version of mihomo")
	RootCmd.PersistentFlags().BoolVarP(&flags.TestConfig, "test", "t", false, "test configuration and exit")
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
