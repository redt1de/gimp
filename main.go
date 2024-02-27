/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package main

import (
	"fmt"
	"log"

	"github.com/redt1de/gimp/pkg/gokrb5"
	"github.com/redt1de/gimp/pkg/gokrb5/types"
)

// TODO:
// test hash auth, works but had to hardcode the etypeid in crypto.GetKeyFromNTLMHash() to 23
// implement GetTGT / GetTGTCCache
// test ldap with st
// mess with smb

const (
	test_user = "jon.snow"
	test_pass = "iknownothing"

	test_hash        = "b8d76e56e9dac90539aff05e3ccb1755"
	test_impersonate = "eddard.stark"
)

func main() {
	// cl := gokrb5.GetKerberosClient("NORTH.SEVENKINGDOMS.LOCAL", "winterfell.NORTH.SEVENKINGDOMS.LOCAL", "jon.snow", "iknownothing", "", false, "aes256-cts-hmac-sha1-96", "", 0)
	cl := gokrb5.GetKerberosClient("NORTH.SEVENKINGDOMS.LOCAL", "winterfell.NORTH.SEVENKINGDOMS.LOCAL", "jon.snow", "", test_hash, false, "aes256-cts-hmac-sha1-96", "", 0)

	fmt.Println(cl.Credentials.HasHash(), cl.Credentials.HasPassword())
	err := cl.Login()
	if err != nil {
		log.Fatal(err)
	}

	cctgt, err := cl.GetTGTAsCCache()
	if err != nil {
		log.Fatal(err)
	}
	cctgt.Export("/tmp/cctgt")

	ccst, err := cl.GetServiceTicketAsCCache("CIFS/winterfell.NORTH.SEVENKINGDOMS.LOCAL")
	if err != nil {
		log.Fatal(err)
	}
	ccst.Export("/tmp/ccst")

	imper := types.PrincipalName{
		NameType: 1,
		NameString: []string{
			"eddard.stark",
		},
	}
	ccsti, err := cl.GetServiceTicketForUserAsCCache("CIFS/winterfell.NORTH.SEVENKINGDOMS.LOCAL", "NORTH.SEVENKINGDOMS.LOCAL", imper)
	if err != nil {
		log.Fatal(err)
	}
	ccsti.Export("/tmp/ccsti")

	// testLDAPwST()
	// return
	// cmd.Execute()
}

// func testLDAPwST() {
// 	c, err := gokrb5.MakeKerbConfig("NORTH.SEVENKINGDOMS.LOCAL", "winterfell.NORTH.SEVENKINGDOMS.LOCAL", 23)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	tryspn := "LDAP/WINTERFELL.NORTH.SEVENKINGDOMS.LOCAL"

// 	// getST and save to ccache
// 	st, err := gokrb5.GetSTCCache("NORTH.SEVENKINGDOMS.LOCAL", "JON.SNOW", "iknownothing", "", false, "winterfell.NORTH.SEVENKINGDOMS.LOCAL", tryspn, "")
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	st.Export("/tmp/abcd.st.ccache")

// 	// load ccache and create client
// 	ccache, _ := credentials.LoadCCache("/tmp/abcd.st.ccache")
// 	cl, err := client.NewFromCCacheEx(ccache, c)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	ok, s := cl.SessionHasSPN(tryspn)
// 	if !ok {
// 		fmt.Println("Current session SPNs:", strings.Join(cl.GetSessionSPNs(), ", "))
// 		log.Fatal("no session for SPN")
// 	}
// 	tryspn = s // match case to the spn in the ccache

// 	// connect to ldap with ST from ccache
// 	var Conn *ldap.Conn
// 	ldapsAddress := fmt.Sprintf("%s:%d", "winterfell.NORTH.SEVENKINGDOMS.LOCAL", 636)
// 	Conn, err = ldap.DialTLS("tcp", ldapsAddress, &tls.Config{InsecureSkipVerify: true})
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	_, err = Conn.GSSAPICCBindCCache(cl, tryspn)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	searchRequest := ldap.NewSearchRequest(
// 		"",
// 		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
// 		"(objectClass=*)",
// 		[]string{"defaultNamingContext"},
// 		nil,
// 	)

// 	sr, err := Conn.Search(searchRequest)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	fmt.Println(sr.Entries[0].GetAttributeValue("defaultNamingContext"))
// }
