/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package main

import (
	"log"

	"github.com/redt1de/gimp/pkg/gokrb5"
	"github.com/redt1de/gimp/pkg/gokrb5/types"
)

// TODO:
// move over the socks code from mfdooom
// test hash auth
// implement GetTGT / GetTGTCCache
// test ldap with st
// mess with smb

func main() {
	cl := gokrb5.GetKerberosClient("NORTH.SEVENKINGDOMS.LOCAL", "winterfell.NORTH.SEVENKINGDOMS.LOCAL", "jon.snow", "iknownothing", "", false, "aes256-cts-hmac-sha1-96", "", 0)
	err := cl.Login()
	if err != nil {
		log.Fatal(err)
	}
	err = cl.Login()
	if err != nil {
		log.Fatal(err)
	}

	cc, err := cl.GetServiceTicketAsCCache("CIFS/winterfell.NORTH.SEVENKINGDOMS.LOCAL")
	if err != nil {
		log.Fatal(err)
	}
	cc.Export("/tmp/ccache")
	// spew.Dump(mt, ek)

	imper := types.PrincipalName{
		NameType: 1,
		NameString: []string{
			"eddard.stark",
		},
	}
	cc2, err := cl.GetServiceTicketForUserAsCCache("CIFS/winterfell.NORTH.SEVENKINGDOMS.LOCAL", "NORTH.SEVENKINGDOMS.LOCAL", imper)
	if err != nil {
		log.Fatal(err)
	}
	cc2.Export("/tmp/ccache2")
	// fmt.Println(mt2.SName.NameString)
	// spew.Dump(cl, ek2)

	// a, err := gokrb5.GetTGTCCache("NORTH.SEVENKINGDOMS.LOCAL", "jon.snow", "iknownothing", "", false, "winterfell.NORTH.SEVENKINGDOMS.LOCAL")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// a.Export("/tmp/a.tgt.ccache")

	// b, err := gokrb5.GetSTCCache("NORTH.SEVENKINGDOMS.LOCAL", "jon.snow", "iknownothing", "", false, "winterfell.NORTH.SEVENKINGDOMS.LOCAL", "CIFS/winterfell.NORTH.SEVENKINGDOMS.LOCAL", "")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// b.Export("/tmp/b.st.ccache")

	// c, err := gokrb5.GetSTCCache("NORTH.SEVENKINGDOMS.LOCAL", "jon.snow", "iknownothing", "", false, "winterfell.NORTH.SEVENKINGDOMS.LOCAL", "CIFS/winterfell.NORTH.SEVENKINGDOMS.LOCAL", "eddard.stark")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// c.Export("/tmp/c.st-imp.ccache")

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
