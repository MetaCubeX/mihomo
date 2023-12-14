package cmd

import (
	"fmt"
	"runtime"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"

	"github.com/spf13/cobra"
)

var commandVersion = &cobra.Command{
	Use:   "version",
	Short: "Show current version of mihomo",
	Run:   cmdPrintVersion,
	Args:  cobra.NoArgs,
}

var nameOnly bool

func init() {
	commandVersion.Flags().BoolVarP(&nameOnly, "name", "n", false, "print version name only")
	RootCmd.AddCommand(commandVersion)
}

func cmdPrintVersion(cmd *cobra.Command, args []string) {
	printVersion()
}

func printVersion() {
	if nameOnly {
		fmt.Printf("Version: %s\n", C.Version)
		return
	}
	versionString := "Mihomo Meta version " + C.Version + "\n\n"
	versionString += "OS: " + runtime.GOOS + "\n" + "Architecture: " + runtime.GOARCH + "\n" + "Go Version: " + runtime.Version() + "\n" + "Build Time: " + C.BuildTime + "\n"

	fmt.Println(versionString)

	if tags := features.Tags(); len(tags) != 0 {
		fmt.Printf("Use tags: %s\n", strings.Join(tags, ", "))
	}
}
