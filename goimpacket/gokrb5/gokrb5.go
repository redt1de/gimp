/*
Package gokrb5 provides a Kerberos 5 implementation for Go.

This is a pure Go implementation and does not have dependencies on native libraries.

Feature include:

# Server Side

HTTP handler wrapper implements SPNEGO Kerberos authentication.

HTTP handler wrapper decodes Microsoft AD PAC authorization data.

# Client Side

Client that can authenticate to an SPNEGO Kerberos authenticated web service.

Ability to change client's password.

# General

Kerberos libraries for custom integration.

Parsing Keytab files.

Parsing krb5.conf files.
*/
package gokrb5

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/redt1de/gimp/goimpacket/gokrb5/client"
	"github.com/redt1de/gimp/goimpacket/gokrb5/config"
	"github.com/redt1de/gimp/goimpacket/gokrb5/credentials"
	"github.com/redt1de/gimp/goimpacket/gokrb5/iana/etypeID"
)

func MakeKerbConfig(domain string, dc string, etypeid int32) (*config.Config, error) {
	c := config.New()
	c.LibDefaults.DefaultRealm = strings.ToUpper(domain)
	c.LibDefaults.PermittedEnctypeIDs = []int32{etypeid}
	c.LibDefaults.PermittedEnctypeIDs = append(c.LibDefaults.PermittedEnctypeIDs, etypeID.RC4_HMAC)
	c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeid}
	c.LibDefaults.DefaultTGSEnctypeIDs = append(c.LibDefaults.DefaultTGSEnctypeIDs, etypeID.RC4_HMAC)
	c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeid}
	c.LibDefaults.DefaultTktEnctypeIDs = append(c.LibDefaults.DefaultTktEnctypeIDs, etypeID.RC4_HMAC)

	c.LibDefaults.UDPPreferenceLimit = 1

	c.LibDefaults.Proxiable = true
	c.LibDefaults.Forwardable = true

	tgsopts := asn1.BitString{}
	tgsopts.Bytes, _ = hex.DecodeString("40810010")
	tgsopts.BitLength = len(tgsopts.Bytes) * 8
	c.LibDefaults.KDCDefaultOptions = tgsopts

	asopts := asn1.BitString{}
	asopts.Bytes, _ = hex.DecodeString("10000000")
	asopts.BitLength = len(asopts.Bytes) * 8
	c.LibDefaults.KDCDefaultOptions = asopts

	var realm config.Realm
	realm.Realm = domain
	realm.KDC = []string{strings.ToUpper(fmt.Sprintf("%s:88", dc))}
	realm.DefaultDomain = domain

	c.Realms = []config.Realm{realm}
	return c, nil
}

// TODO:
// need to iterate through the etypes if KDC_ERR_ETYPE_NOSUPP is returned
func GetKerberosClient(domain string, dc string, username string, password string, ntlm string, ccachePath string, etype string, socksAddress string, socksType int) *client.Client {
	var cl *client.Client
	var err error

	etypeid := etypeID.EtypeSupported(etype)
	if etypeid == 0 {
		log.Println("Invalid E-type ID requested for Kerberos Client")
		fmt.Println("Valid types are:")
		for k, v := range etypeID.ETypesByName {
			fmt.Printf("%s: %d\n", k, v)
		}
	}
	if ntlm != "" {
		etypeid = etypeID.RC4_HMAC
	}

	domain = strings.ToUpper(domain)
	c, err := MakeKerbConfig(domain, dc, etypeid)
	if err != nil {
		log.Fatal(err)
	}

	if ccachePath != "" {
		ccache, _ := credentials.LoadCCache(ccachePath)
		cl, err = client.NewFromCCache(ccache, c)
		if err != nil {
			log.Fatal(err)
		}
	} else if password != "" {
		cl = client.NewWithPassword(username, domain, password, c, client.DisablePAFXFAST(true), client.AssumePreAuthentication(false))
	} else if ntlm != "" {

		cl = client.NewWithHash(username, domain, ntlm, c, client.DisablePAFXFAST(true), client.AssumePreAuthentication(false))
	}

	return cl

}

// TODO:
// need to iterate through the etypes if KDC_ERR_ETYPE_NOSUPP is returned
func GetKerberosClientEx(domain string, dc string, username string, password string, ntlm string, ccachePath string, socksAddress string, socksType int) *client.Client {
	var cl *client.Client
	var err error

	// etypeid := etypeID.EtypeSupported(etype)
	// if etypeid == 0 {
	// 	log.Println("Invalid E-type ID requested for Kerberos Client")
	// 	fmt.Println("Valid types are:")
	// 	for k, v := range etypeID.ETypesByName {
	// 		fmt.Printf("%s: %d\n", k, v)
	// 	}
	// }
	etypeid := etypeID.AES256_CTS_HMAC_SHA1_96

	if ntlm != "" {
		etypeid = etypeID.RC4_HMAC
	}

	domain = strings.ToUpper(domain)
	c, err := MakeKerbConfig(domain, dc, etypeid)
	if err != nil {
		log.Fatal(err)
	}

	if ccachePath != "" {
		ccache, _ := credentials.LoadCCache(ccachePath)
		cl, err = client.NewFromCCacheEx(ccache, c)
		if err != nil {
			log.Fatal(err)
		}
	} else if password != "" {
		cl = client.NewWithPassword(username, domain, password, c, client.DisablePAFXFAST(true), client.AssumePreAuthentication(false))
	} else if ntlm != "" {

		cl = client.NewWithHash(username, domain, ntlm, c, client.DisablePAFXFAST(true), client.AssumePreAuthentication(false))
	}

	return cl

}
