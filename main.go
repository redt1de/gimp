/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package main

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/redt1de/gimp/pkg/go-smb2"
	"github.com/redt1de/gimp/pkg/goimpacket"
	"github.com/redt1de/gimp/pkg/gokrb5"
	"github.com/redt1de/gimp/pkg/gokrb5/client"
	"github.com/redt1de/gimp/pkg/gokrb5/credentials"
	"github.com/redt1de/gimp/pkg/gokrb5/types"
	"github.com/redt1de/gimp/pkg/ldap"
)

// TODO:
// get rid of the etypeid in MakeKerbConfig/Getkerbclient
// mess with smb
// smb needs ntlmv1 support

const (
	test_domain      = "NORTH.SEVENKINGDOMS.LOCAL"
	test_dc          = "winterfell.NORTH.SEVENKINGDOMS.LOCAL"
	test_user        = "jon.snow"
	test_pass        = "iknownothing"
	test_hash        = "b8d76e56e9dac90539aff05e3ccb1755"
	test_hash_full   = "aad3b435b51404eeaad3b435b51404ee:b8d76e56e9dac90539aff05e3ccb1755"
	test_impersonate = "eddard.stark"
	test_spn_cifs    = "CIFS/winterfell.NORTH.SEVENKINGDOMS.LOCAL"
	test_spn_ldap    = "LDAP/winterfell.NORTH.SEVENKINGDOMS.LOCAL"
)

func main() {
	testSMBConn()
	// testLdapConn()
	// testSmbKerbST()
	// testTickets()
	// testLDAPwST()
	// testSmbNtlm()
	// testSmbKerb()

	// cmd.Execute()
}

func testSMBConn() {
	fmt.Println("[+] Testing SMB...")
	// l := goimpacket.NewSMBConnection(test_domain, test_dc, test_user, test_pass, "", true, "/tmp/jstgt.ccache", test_dc) // krb TGT
	// l := goimpacket.NewSMBConnection(test_domain, test_dc, test_user, test_pass, "", true, "/tmp/jscifs.ccache", test_dc) // krb ST
	// l := goimpacket.NewSMBConnection(test_domain, test_dc, test_user, "", test_hash, true, "", test_dc) // krb hash
	// l := goimpacket.NewSMBConnection(test_domain, test_dc, test_user, test_pass, "", true, "", test_dc) // krb pass
	l := goimpacket.NewSMBConnection(test_domain, test_dc, test_user, "", test_hash, false, "", test_dc) // ntlm hash
	// l := goimpacket.NewSMBConnection(test_domain, test_dc, test_user, test_pass, "", false, "", test_dc) // ntlm pass
	err := l.Login()
	if err != nil {
		log.Fatal(err)
	}

	names, err := l.SmbConn.ListSharenames()
	if err != nil {
		log.Fatal(err)
	}

	for _, name := range names {
		fmt.Println(name)
	}

}

func testLdapConn() {
	fmt.Println("[+] Testing LDAP...")
	// l := goimpacket.NewLDAPConnection(test_domain, test_dc, 636, test_user, test_pass, "", true, "/tmp/jstgt.ccache", test_dc, true) // krb TGT
	// l := goimpacket.NewLDAPConnection(test_domain, test_dc, 636, test_user, test_pass, "", true, "/tmp/jsldap.ccache", test_dc, true) // krb ST
	// l := goimpacket.NewLDAPConnection(test_domain, test_dc, 636, test_user, "", test_hash, true, "", test_dc, true) // krb hash
	// l := goimpacket.NewLDAPConnection(test_domain, test_dc, 636, test_user, test_pass, "", true, "", test_dc, true) // krb pass
	// l := goimpacket.NewLDAPConnection(test_domain, test_dc, 636, test_user, "", test_hash, false, "", test_dc, true) // ntlm hash
	l := goimpacket.NewLDAPConnection(test_domain, test_dc, 636, test_user, test_pass, "", false, "", test_dc, true) // ntlm pass
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

func testSmbNtlm() {
	fmt.Println("[+] Testing SMB ntlm...")
	conn, err := net.Dial("tcp", "192.168.56.11:445")
	// conn, err := net.Dial("tcp", "192.168.56.1:445")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	hashhex, err := hex.DecodeString(test_hash)
	if err != nil {
		panic(err)
	}
	spew.Dump(hashhex)

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User: "JON.SNOW",
			// Password: "iknownothing",
			Hash: hashhex,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		panic(err)
	}
	defer s.Logoff()

	names, err := s.ListSharenames()
	if err != nil {
		panic(err)
	}

	for _, name := range names {
		fmt.Println(name)
	}
}

func testSmbKerb() {
	fmt.Println("[+] Testing SMB kerb pass...")
	conn, err := net.Dial("tcp", "192.168.56.11:445")
	// conn, err := net.Dial("tcp", "192.168.56.1:445")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// session.go:244

	////////////////////////
	// kerberos auth works.
	cl := gokrb5.GetKerberosClientEx(test_domain, test_dc, test_user, test_pass, "", "", "", 0)
	// cl := gokrb5.GetKerberosClient(test_domain, test_dc, test_user, "", test_hash, false,  "", 0)
	err = cl.Login()
	if err != nil {
		log.Fatal(err)
	}
	d := &smb2.Dialer{
		Initiator: &smb2.KerberosInitiator{
			SPN:    test_spn_cifs,
			Client: cl,
			User:   cl.Credentials.CName(),
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		panic(err)
	}
	defer s.Logoff()

	names, err := s.ListSharenames()
	if err != nil {
		panic(err)
	}

	for _, name := range names {
		fmt.Println(name)
	}
}

func testSmbKerbST() {
	fmt.Println("[+] Testing SMB kerb ST...")
	cl := gokrb5.GetKerberosClientEx(test_domain, test_dc, test_user, test_pass, "", "", "", 0)
	// cl := gokrb5.GetKerberosClientEx(test_domain, test_dc, test_user, "", test_hash, false,  "", 0)
	err := cl.Login()
	if err != nil {
		log.Fatal(err)
	}

	ccst, err := cl.GetServiceTicketAsCCache(test_spn_cifs)
	if err != nil {
		log.Fatal(err)
	}
	ccst.Export("/tmp/ccstsmb")

	// load ccache and create client
	ccache, _ := credentials.LoadCCache("/tmp/ccstsmb")
	cl2, err := client.NewFromCCacheEx(ccache, cl.Config)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.Dial("tcp", "192.168.56.11:445")
	// conn, err := net.Dial("tcp", "192.168.56.1:445")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.KerberosInitiator{
			SPN:    test_spn_cifs,
			Client: cl2,
			User:   cl2.Credentials.CName(),
		},
	}

	fmt.Println(cl.GetSessionSPNs())
	s, err := d.Dial(conn)
	if err != nil {
		panic(err)
	}
	defer s.Logoff()

	names, err := s.ListSharenames()
	if err != nil {
		panic(err)
	}

	for _, name := range names {
		fmt.Println(name)
	}
}

func testLDAPwST() {
	cl := gokrb5.GetKerberosClientEx(test_domain, test_dc, test_user, test_pass, "", "", "", 0)
	// cl := gokrb5.GetKerberosClient(test_domain, test_dc, test_user, "", test_hash, false,  "", 0)
	err := cl.Login()
	if err != nil {
		log.Fatal(err)
	}

	ccst, err := cl.GetServiceTicketAsCCache(test_spn_ldap)
	if err != nil {
		log.Fatal(err)
	}
	ccst.Export("/tmp/ccst")

	// load ccache and create client
	ccache, _ := credentials.LoadCCache("/tmp/ccst")
	cl2, err := client.NewFromCCacheEx(ccache, cl.Config)
	if err != nil {
		log.Fatal(err)
	}

	ok, s := cl2.SessionHasSPN(test_spn_ldap)
	if !ok {
		fmt.Println("Current session SPNs:", strings.Join(cl2.GetSessionSPNs(), ", "))
		log.Fatal("no session for SPN")
	}
	tryspn := s // match case to the spn in the ccache

	// connect to ldap with ST from ccache
	var Conn *ldap.Conn
	ldapsAddress := fmt.Sprintf("%s:%d", test_dc, 636)
	Conn, err = ldap.DialTLS("tcp", ldapsAddress, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Fatal(err)
	}
	_, err = Conn.GSSAPICCBindCCache(cl, tryspn)
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
