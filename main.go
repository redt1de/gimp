/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package main

import (
	"fmt"
	"log"

	"github.com/redt1de/dbg"
	"github.com/redt1de/gimp/goimpacket"
	"github.com/redt1de/gimp/goimpacket/gokrb5"
	"github.com/redt1de/gimp/goimpacket/gokrb5/types"
	"github.com/redt1de/gimp/goimpacket/ldap"
	"github.com/redt1de/gimp/goimpacket/util"
)

// TODO:

const (
	test_domain      = "NORTH.SEVENKINGDOMS.LOCAL"
	test_dc          = "winterfell.NORTH.SEVENKINGDOMS.LOCAL"
	test_host        = "winterfell.NORTH.SEVENKINGDOMS.LOCAL"
	test_user        = "jon.snow"
	test_pass        = "iknownothing"
	test_hash        = "b8d76e56e9dac90539aff05e3ccb1755"
	test_hash_full   = "aad3b435b51404eeaad3b435b51404ee:b8d76e56e9dac90539aff05e3ccb1755"
	test_impersonate = "eddard.stark"
	test_spn_cifs    = "CIFS/winterfell.NORTH.SEVENKINGDOMS.LOCAL"
	test_spn_ldap    = "LDAP/winterfell.NORTH.SEVENKINGDOMS.LOCAL"
	// test_domain      = "ESSOS.LOCAL"
	// test_dc          = "MEEREEN.ESSOS.LOCAL"
	// test_host        = "BRAAVOS.ESSOS.LOCAL"
	// test_user        = "daenerys.targaryen"
	// test_pass        = "BurnThemAll!"
	// test_hash        = ""
	// test_hash_full   = ""
	// test_impersonate = ""
	// test_spn_cifs    = "CIFS/MEEREEN.ESSOS.LOCAL"
	// test_spn_ldap    = "LDAP/MEEREEN.ESSOS.LOCAL"
)

func main() {
	dbg.SetByName("session2", true, dbg.LogAll^dbg.LogErrTrace^dbg.LogTraceVerbose) // defined as a globar var in session2.go so should already exist
	dbg.SetByName("main", true, dbg.LogDefault)
	dbg.SetByName("smb", true, dbg.LogDefault^dbg.LogInfo|dbg.LogErrorSrc)
	dbg.SetByName("gssapi2", true, dbg.LogAll)

	// testSMBConn()
	// testLdapConn()
	// testTickets()

	// cmd.Execute()

	fmt.Println(util.ParseTarget("NORTH.SEVENKINGDOMS.LOCAL/jon.snow:iknownothing@somehost.somedom.com"))
	fmt.Println(util.ParseTarget("NORTH.SEVENKINGDOMS.LOCAL\\jon.snow:iknownothing@somehost.somedom.com"))
	fmt.Println(util.ParseTarget("NORTH.SEVENKINGDOMS.LOCAL\\jon.snow@somehost.somedom.com"))
	fmt.Println(util.ParseTarget("NORTH.SEVENKINGDOMS.LOCAL\\jon.snow"))
}

func testSMBConn() {
	fmt.Println("[+] Testing SMB...")
	// l := goimpacket.NewSMBConnection(test_domain, test_dc, test_user, test_pass, "", true, "/tmp/jstgt.ccache", test_dc) // krb TGT
	// l := goimpacket.NewSMBConnection(test_domain, test_dc, test_user, test_pass, "", true, "/tmp/jscifs.ccache", test_dc) // krb ST
	// l := goimpacket.NewSMBConnection(test_domain, test_dc, test_user, "", test_hash, true, "", test_dc) // krb hash
	// l := goimpacket.NewSMBConnection(test_domain, test_host, test_user, test_pass, "", true, "", test_dc) // krb pass
	// l := goimpacket.NewSMBConnection(test_domain, test_dc, test_user, "", test_hash, false, "", test_dc) // ntlm hash
	l := goimpacket.NewSMBConnection(test_domain, test_dc, test_user, test_pass, "", false, "", test_dc) // ntlm pass
	err := l.Login()
	if err != nil {
		log.Fatal(err)
	}

	// names, err := l.SmbSession.ListSharenames()
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// for _, name := range names {
	// 	fmt.Println(name)
	// }

}

func testLdapConn() {
	fmt.Println("[+] Testing LDAP...")
	// l := goimpacket.NewLDAPConnection(test_domain, test_dc, 636, test_user, test_pass, "", true, "/tmp/jstgt.ccache", test_dc, true) // krb TGT
	// l := goimpacket.NewLDAPConnection(test_domain, test_dc, 636, test_user, test_pass, "", true, "/tmp/jsldap.ccache", test_dc, true) // krb ST
	// l := goimpacket.NewLDAPConnection(test_domain, test_dc, 636, test_user, "", test_hash, true, "", test_dc, true) // krb hash
	l := goimpacket.NewLDAPConnection(test_domain, test_dc, 636, test_user, test_pass, "", true, "", test_dc, true) // krb pass
	// l := goimpacket.NewLDAPConnection(test_domain, test_dc, 636, test_user, "", test_hash, false, "", test_dc, true) // ntlm hash
	// l := goimpacket.NewLDAPConnection(test_domain, test_dc, 636, test_user, test_pass, "", false, "", test_dc, true) // ntlm pass
	err := l.Login()
	if err != nil {
		log.Fatal(err)
	}

	sr, err := l.Conn.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(sr.Entries[0].GetAttributeValue("defaultNamingContext"))

}

func testTickets() {
	fmt.Println("[+] Testing tickets...")
	cl := gokrb5.GetKerberosClientEx(test_domain, test_dc, test_user, test_pass, "", "", "", 0)
	// cl := gokrb5.GetKerberosClientEx(test_domain, test_dc, test_user, "", test_hash, false,  "", 0)
	err := cl.Login()
	if err != nil {
		log.Fatal(err)
	}

	cctgt, err := cl.GetTGTAsCCache()
	if err != nil {
		log.Fatal(err)
	}
	cctgt.Export("/tmp/cctgt")

	ccst, err := cl.GetServiceTicketAsCCache(test_spn_cifs)
	if err != nil {
		log.Fatal(err)
	}
	ccst.Export("/tmp/ccst")

	imper := types.PrincipalName{
		NameType: 1,
		NameString: []string{
			test_impersonate,
		},
	}
	ccsti, err := cl.GetServiceTicketForUserAsCCache(test_spn_cifs, test_domain, imper)
	if err != nil {
		log.Fatal(err)
	}
	ccsti.Export("/tmp/ccsti")

}
