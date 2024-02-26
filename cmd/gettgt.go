/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/spf13/cobra"
)

// gettgtCmd represents the gettgt command
var gettgtCmd = &cobra.Command{
	Use:   "gettgt",
	Short: "Request a Ticket Granting Ticket (TGT) from the KDC.",
	Long:  `Request a Ticket Granting Ticket (TGT) from the KDC and save it as CCACHE file`,
	Run: func(cmd *cobra.Command, args []string) {
		// domain, _ := cmd.Flags().GetString("domain")
		// dcip, _ := cmd.Flags().GetString("dcip")
		// user, _ := cmd.Flags().GetString("user")
		// pass, _ := cmd.Flags().GetString("pass")
		// hash, _ := cmd.Flags().GetString("hash")
		// ccacheAuth, _ := cmd.Flags().GetString("ccache")
		// outputfile, _ := cmd.Flags().GetString("outputfile")
		// kerberos, _ := cmd.Flags().GetBool("kerberos")

		// if ccacheAuth != "" {
		// 	kerberos = true
		// }

		// cl := gokrb5.GetKerberosClient(domain, dcip, user, pass, hash, kerberos, "aes256-cts-hmac-sha1-96", "", 0)
		// err := cl.Login()
		// if err != nil {
		// 	log.Fatal(err)
		// }

		// ASReq, err := messages.NewASReqForTGT(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
		// if err != nil {
		// 	log.Fatal(err)
		// }

		// ASRep, err := cl.ASExchange(cl.Credentials.Domain(), ASReq, 0)
		// if err != nil {
		// 	log.Fatal(err)
		// }

		// cc, err := ASRep.ToCCache()

		// if err != nil {
		// 	log.Fatal(err)
		// }
		// if outputfile == "" {
		// 	outputfile = "./" + user + ".tgt.ccache"
		// }
		// fmt.Println("[+] Saving TGT to", outputfile)
		// cc.Export(outputfile)
	},
}

func init() {
	rootCmd.AddCommand(gettgtCmd)
	gettgtCmd.Flags().StringP("ccache", "c", "", "CCACHE file if not using KRB5CCNAME, implies -k")
	gettgtCmd.Flags().BoolP("kerberos", "k", false, "use kerberos ticket for authentication (KRB5CCNAME|--ccache required)")
	gettgtCmd.Flags().StringP("dcip", "D", "", "Domain Controller IP address, if null will use FQDN of user domain.")
	gettgtCmd.Flags().StringP("user", "u", "", "Username to authenticate with")
	gettgtCmd.Flags().StringP("pass", "p", "", "Password to authenticate with")
	gettgtCmd.Flags().StringP("hash", "H", "", "NTLM hash to authenticate with")
	gettgtCmd.Flags().StringP("domain", "d", "", "Domain to authenticate with")
	gettgtCmd.Flags().StringP("outputfile", "o", "", "Output file for the TGT, defaults to ./<user>.tgt.ccache")

	gettgtCmd.MarkFlagRequired("domain")
}
