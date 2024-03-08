/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/redt1de/gimp/goimpacket"
	"github.com/spf13/cobra"
)

// gettgtCmd represents the gettgt command
var gettgtCmd = &cobra.Command{
	Aliases: []string{"tgt"},
	Short:   "Request a Ticket Granting Ticket (TGT) from the KDC.",
	Long:    `Request a Ticket Granting Ticket (TGT) from the KDC and save it as CCACHE file`,
	Args:    cobra.MinimumNArgs(1),
	Use:     "gettgt [flags] <domain/username[:password]>",
	Run: func(cmd *cobra.Command, args []string) {
		handlePersistantFlags(cmd)
		ad, err := goimpacket.NewADAccountFromString(args[len(args)-1])
		if err != nil {
			clilog.Errorf("Error parsing target string: %s", err.Error())
			return
		}

		outfile, _ := cmd.Flags().GetString("outfile")
		if outfile == "" {
			outfile = "./" + ad.Username + ".tgt.ccache"
		}
		hash, _ := cmd.Flags().GetString("hash")
		if hash != "" {
			ad.Hash = hash
		}
		dc, _ := cmd.Flags().GetString("dc")
		if dc != "" {
			ad.DC = dc
		} else {
			ad.DC = ad.Domain
		}

		err = goimpacket.GetTGT(ad, outfile)
		if err != nil {
			clilog.Errorf("Error getting TGT: %s", err.Error())
			return
		}
		clilog.Successf("Ticket Granting Ticket saved to %s", outfile)

	},
}

func init() {
	rootCmd.AddCommand(gettgtCmd)
	gettgtCmd.Flags().StringP("dc", "D", "", "Domain Controller, if null will use FQDN of user domain.")
	gettgtCmd.Flags().StringP("hash", "H", "", "NTLM hash to authenticate with")
	gettgtCmd.Flags().StringP("outfile", "o", "", "Output file for the TGT, defaults to ./<user>.tgt.ccache")

}
