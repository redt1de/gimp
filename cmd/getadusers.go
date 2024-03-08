/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/redt1de/gimp/goimpacket"
	"github.com/redt1de/gimp/goimpacket/ldap"
	"github.com/spf13/cobra"
)

// getadusersCmd represents the getadusers command
var getadusersCmd = &cobra.Command{
	Use:   "getadusers",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		handlePersistantFlags(cmd)
		ad, err := goimpacket.NewADAccountFromString(args[len(args)-1])
		if err != nil {
			clilog.Errorf("Error parsing target string: %s", err.Error())
			return
		}

		at, err := goimpacket.NewADTargetFromString(args[len(args)-1])
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

		ld := goimpacket.NewLDAPConnection(ad, at, false)
		err = ld.Login()
		if err != nil {
			clilog.Errorf("Error connecting to LDAP: %s", err.Error())
			return
		}
		defer ld.Close()
		sr, err := ld.Conn.Search(ldap.NewSearchRequest(
			ld.BaseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			"(&(sAMAccountName=*)(objectCategory=user))",
			[]string{"sAMAccountName", "pwdLastSet", "mail", "lastLogon"},
			nil,
		))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Name                  Email                           PasswordLastSet      LastLogon")
		fmt.Println("--------------------  ------------------------------  -------------------  -------------------")

		for _, entry := range sr.Entries {
			sAMAccountName := entry.GetAttributeValue("sAMAccountName")
			pwdLastSet := entry.GetAttributeValue("pwdLastSet")
			mail := entry.GetAttributeValue("mail")
			lastLogon := entry.GetAttributeValue("lastLogon")
			fmt.Printf("%-20s  %-30s  %-20s  %-20s\n", sAMAccountName, mail, ldapTime(pwdLastSet), ldapTime(lastLogon))
		}

	},
}

func ldapTime(ntTimeStr string) string {
	// Convert the Windows NT time from string to int64
	ntTimeInt, err := strconv.ParseInt(ntTimeStr, 10, 64)
	if err != nil {
		return ""
	}

	// Convert the Windows NT time to nanoseconds (from 100-nanosecond intervals)
	ntTimeNano := ntTimeInt * 100

	// The duration from the Windows NT base time to Unix base time (1970-01-01)
	// Windows NT base time (1601-01-01) to Unix base time (1970-01-01) in nanoseconds
	unixTimeOffset := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()

	// Calculate the Unix time in nanoseconds
	unixTimeNano := ntTimeNano + unixTimeOffset

	// Convert to time.Time
	// Format the time to RFC 3339 or any other desired format
	formattedTime := time.Unix(0, unixTimeNano).Format(time.UnixDate)

	return formattedTime

}

func init() {
	rootCmd.AddCommand(getadusersCmd)
	getadusersCmd.Flags().StringP("dc", "D", "", "Domain Controller, if null will use FQDN of user domain.")
	getadusersCmd.Flags().StringP("hash", "H", "", "NTLM hash to authenticate with")
	getadusersCmd.Flags().StringP("outfile", "o", "", "Output file for the TGT, defaults to ./<user>.tgt.ccache")
}
