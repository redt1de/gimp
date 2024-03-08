/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	"github.com/redt1de/dbg"
	"github.com/spf13/cobra"
)

var clilog = dbg.Get("cli")

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gimp",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		verbose, _ := cmd.Flags().GetBool("verbose")
		veryVerbose, _ := cmd.Flags().GetBool("very-verbose")
		// debug, _ := cmd.Flags().GetBool("debug")
		if veryVerbose {
			verbose = true
			dbg.SetAll(true, dbg.LogAll)
			return
		}
		if verbose {
			dbg.SetAll(true, dbg.LogError|dbg.LogWarn|dbg.LogDebug|dbg.LogInfo|dbg.LogSuccess)
			return
		}
		dbg.SetAll(false, dbg.LogError|dbg.LogWarn|dbg.LogInfo|dbg.LogSuccess)

	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.gimp.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	// rootCmd.PersistentFlags().Bool("debug", false, "enable debug output")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "enable verbose output")
	rootCmd.PersistentFlags().BoolP("very-verbose", "V", false, "enable verbose output")

}

func handlePersistantFlags(cmd *cobra.Command) {
	verbose, _ := cmd.Flags().GetBool("verbose")
	veryVerbose, _ := cmd.Flags().GetBool("very-verbose")
	if veryVerbose {
		verbose = true
		dbg.SetAll(true, dbg.LogAll)
		return
	}
	if verbose {
		dbg.SetAll(true, dbg.LogError|dbg.LogWarn|dbg.LogDebug|dbg.LogInfo|dbg.LogSuccess)
		return
	}
	dbg.SetAll(true, dbg.LogError|dbg.LogWarn|dbg.LogInfo|dbg.LogSuccess)
}
