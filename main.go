/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package main

import (
	"fmt"
	"log"

	"github.com/redt1de/dbg"
	"github.com/redt1de/gimp/cmd"
	"github.com/redt1de/gimp/goimpacket"
	"github.com/redt1de/gimp/goimpacket/gokrb5"
	"github.com/redt1de/gimp/goimpacket/gokrb5/types"
	"github.com/redt1de/gimp/goimpacket/ldap"
)

// TODO:
// - [ ] GetTGT with hash fails, ccache is bad format

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

var (
// jsNorth = goimpacket.NewADTarget(test_domain, test_dc, test_user, test_pass, "", true, "/tmp/jstgt.ccache", test_dc)
)

func main() {
	dbg.SetByName("session2", true, dbg.LogAll^dbg.LogErrTrace^dbg.LogTraceVerbose) // defined as a globar var in session2.go so should already exist
	dbg.SetByName("main", true, dbg.LogDefault)
	dbg.SetByName("smb", true, dbg.LogDefault^dbg.LogInfo|dbg.LogErrorSrc)
	dbg.SetByName("gssapi2", true, dbg.LogAll)
	dbg.SetByName("gokrb5/spnego", true, dbg.LogAll)

	// need a func to get DC from domain

	// testSMBConn()
	// testLdapConn()
	// testTickets()
	// wtf()

	cmd.Execute()

}

func testSMBConn() {
	fmt.Println("[+] Testing SMB...")
	// l := goimpacket.NewSMBConnection(test_domain, test_dc, test_user, test_pass, "", true, "/tmp/jstgt.ccache", test_dc) // krb TGT
	// l := goimpacket.NewSMBConnection(test_domain, test_dc, test_user, test_pass, "", true, "/tmp/jscifs.ccache", test_dc) // krb ST
	// l := goimpacket.NewSMBConnection(test_domain, test_dc, test_user, "", test_hash, true, "", test_dc) // krb hash
	// l := goimpacket.NewSMBConnection(test_domain, test_host, test_user, test_pass, "", true, "", test_dc) // krb pass
	// l := goimpacket.NewSMBConnection(test_domain, test_dc, test_user, "", test_hash, false, "", test_dc) // ntlm hash
	// l := goimpacket.NewSMBConnection(test_domain, test_dc, test_user, test_pass, "", false, "", test_dc) // ntlm pass
	// l := goimpacket.NewSMBConnection(jsNorth)
	// err := l.Login()
	// if err != nil {
	// 	log.Fatal(err)
	// }

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
	// l := goimpacket.NewLDAPConnection(test_domain, test_dc,  test_user, test_pass, "", true, "/tmp/jstgt.ccache", test_dc, true) // krb TGT
	// l := goimpacket.NewLDAPConnection(test_domain, test_dc, test_user, test_pass, "", true, "/tmp/jstgt.ccache", test_dc, false) // krb TGT plain
	// l := goimpacket.NewLDAPConnection(test_domain, test_dc,  test_user, test_pass, "", true, "/tmp/jsldap.ccache", test_dc, true) // krb ST
	// l := goimpacket.NewLDAPConnection(test_domain, test_dc,  test_user, "", test_hash, true, "", test_dc, true) // krb hash
	// l := goimpacket.NewLDAPConnection(test_domain, test_dc,  test_user, test_pass, "", true, "", test_dc, true) // krb pass
	// l := goimpacket.NewLDAPConnection(test_domain, test_dc,  test_user, "", test_hash, false, "", test_dc, true) // ntlm hash
	// l := goimpacket.NewLDAPConnection(test_domain, test_dc,  test_user, test_pass, "", false, "", test_dc, true) // ntlm pass
	// l := goimpacket.NewLDAPConnection(test_domain, test_dc, test_user, test_pass, "", true, "/tmp/jstgt.ccache", test_dc, true)
	l := goimpacket.NewLDAPConnection(&goimpacket.ADAccount{}, &goimpacket.ADTarget{}, false)

	err := l.Login()
	if err != nil {
		log.Fatal(err)
	}
	defer l.Conn.Close()
	// l.Conn.Debug = true

	sr, err := l.Conn.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 1, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	))
	if err != nil {
		log.Fatal(err)
	}

	basedn := sr.Entries[0].GetAttributeValue("defaultNamingContext")
	fmt.Println("BaseDN:", basedn)

	// searchFilter := "(&(|(UserAccountControl:1.2.840.113556.1.4.803:=16777216)(UserAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(UserAccountControl:1.2.840.113556.1.4.803:=8192)))"

	// // sr, err = l.Conn.Search(ldap.NewSearchRequest(basedn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, searchFilter, []string{"sAMAccountName"}, nil))
	// sr, err = l.Conn.Search(ldap.NewSearchRequest(
	// 	"",
	// 	ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
	// 	searchFilter,
	// 	[]string{"samAccountName"},
	// 	nil,
	// ))
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// dbg.Dump(sr)

}

func wtf() {
	fmt.Println("[+] Testing tickets (pass) ...")
	cl := gokrb5.GetKerberosClientEx(test_domain, test_dc, test_user, test_pass, "", "", "", 0)
	// cl := gokrb5.GetKerberosClientEx(test_domain, test_dc, test_user, "", test_hash, "", "", 0)
	err := cl.Login()
	if err != nil {
		log.Fatal(err)
	}
	err = cl.CCache.Export("/tmp/cctgt.pass")
	if err != nil {
		log.Fatal(err)
	}

	// fmt.Println("[+] Testing tickets (hash) ...")
	// cl2 := gokrb5.GetKerberosClientEx(test_domain, test_dc, test_user, "", test_hash, "", "", 0)
	// err = cl2.Login()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// err = cl2.CCache.Export("/tmp/cctgt.hash")
	// if err != nil {
	// 	log.Fatal(err)
	// }

}

func testTickets() {
	fmt.Println("[+] Testing tickets...")
	cl := gokrb5.GetKerberosClientEx(test_domain, test_dc, test_user, test_pass, "", "", "", 0)
	// cl := gokrb5.GetKerberosClientEx(test_domain, test_dc, test_user, "", test_hash, "", "", 0)
	err := cl.Login()
	if err != nil {
		log.Fatal(err)
	}

	err = cl.CCache.Export("/tmp/cctgt")
	if err != nil {
		log.Fatal(err)
	}

	cl2 := gokrb5.GetKerberosClientEx(test_domain, test_dc, test_user, "", "", "/tmp/cctgt", "", 0)
	err = cl2.Login()
	if err != nil {
		log.Fatal(err)
	}
	ccst, err := cl2.GetServiceTicketAsCCache(test_spn_cifs)
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
