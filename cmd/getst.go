/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"strings"

	"github.com/redt1de/gimp/goimpacket"
	"github.com/spf13/cobra"
)

// getstCmd represents the getst command
var getstCmd = &cobra.Command{
	Aliases: []string{"st"},
	Short:   "Request a Service Ticket (TGT) from the KDC.",
	Long:    `Request a Service Ticket (TGT) from the KDC and save it as CCACHE file`,
	Args:    cobra.MinimumNArgs(1),
	Use:     "getst [flags] <domain/username[:password]>",
	Run: func(cmd *cobra.Command, args []string) {
		handlePersistantFlags(cmd)
		ad, err := goimpacket.NewADAccountFromString(args[len(args)-1])
		if err != nil {
			clilog.Errorf("Error parsing target string: %s", err.Error())
			return
		}
		spn, _ := cmd.Flags().GetString("spn")
		impersonate, _ := cmd.Flags().GetString("impersonate")

		kerb, _ := cmd.Flags().GetBool("kerberos")
		ccache, _ := cmd.Flags().GetString("ccache")
		if ccache != "" || kerb {
			ad.CCachePath = ccache
			ad.Kerberos = true
		}

		outfile, _ := cmd.Flags().GetString("outfile")
		if outfile == "" {
			outfile = "./" + ad.Username + "." + strings.ReplaceAll(spn, "/", "_") + ".st.ccache"
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
		err = goimpacket.GetST(ad, spn, impersonate, outfile)
		if err != nil {

			clilog.Errorf("Error getting ST: %s", err.Error())

			return
		}
		clilog.Successf("Service Ticket saved to %s", outfile)
	},
}

func init() {
	rootCmd.AddCommand(getstCmd)

	getstCmd.Flags().StringP("ccache", "c", "", "CCACHE file if not using KRB5CCNAME, implies -k")
	getstCmd.Flags().BoolP("kerberos", "k", false, "use kerberos ticket for authentication (KRB5CCNAME|--ccache required)")
	getstCmd.Flags().StringP("dc", "D", "", "Domain Controller, if null will use FQDN of user domain.")
	getstCmd.Flags().StringP("spn", "s", "", "SPN to request a ticket for")
	getstCmd.Flags().StringP("impersonate", "I", "", "Account to impersonate via S4U2Self")
	getstCmd.Flags().StringP("hash", "H", "", "NTLM hash to authenticate with")
	getstCmd.Flags().StringP("outfile", "o", "", "Output file for the TGT, defaults to ./<user>.tgt.ccache")

	getstCmd.MarkFlagRequired("spn")
}
