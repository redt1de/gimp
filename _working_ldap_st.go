package main

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/redt1de/gimp/pkg/gokrb5"
	"github.com/redt1de/gimp/pkg/gokrb5/client"
	"github.com/redt1de/gimp/pkg/gokrb5/credentials"
	"github.com/redt1de/gimp/pkg/ldap"
)

func test() {
	c, err := gokrb5.MakeKerbConfig("NORTH.SEVENKINGDOMS.LOCAL", "winterfell.NORTH.SEVENKINGDOMS.LOCAL", 23)
	if err != nil {
		log.Fatal(err)
	}
	ccache, _ := credentials.LoadCCache("/opt/impacket/jon.snow.ccache")
	// spew.Dump(ccache)

	cl, err := client.NewFromCCacheEx(ccache, c)
	if err != nil {
		log.Fatal(err)
	}
	// err = cl.Login()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(cl.Credentials.UserName())

	var Conn *ldap.Conn
	ldapsAddress := fmt.Sprintf("%s:%d", "winterfell.NORTH.SEVENKINGDOMS.LOCAL", 636)
	Conn, err = ldap.DialTLS("tcp", ldapsAddress, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Fatal(err)
	}
	_, err = Conn.GSSAPICCBindCCache(cl, "LDAP/winterfell.NORTH.SEVENKINGDOMS.LOCAL")
	if err != nil {
		log.Fatal(err)
	}
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)

	sr, err := Conn.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(sr.Entries[0].GetAttributeValue("defaultNamingContext"))
}
