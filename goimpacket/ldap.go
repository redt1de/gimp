package goimpacket

import (
	"crypto/tls"
	"fmt"

	"github.com/redt1de/gimp/goimpacket/gokrb5"
	"github.com/redt1de/gimp/goimpacket/gokrb5/client"
	"github.com/redt1de/gimp/goimpacket/ldap"
)

type LDAPConnection struct {
	Domain      string
	Host        string
	Port        int
	Username    string
	Password    string
	Hash        string
	Kerberos    bool
	CCachePath  string
	DC          string
	TLS         bool
	Conn        *ldap.Conn
	ldapAddress string
}

// NewLDAPConnection creates a new LDAPConnection object
func NewLDAPConnection(domain string, host string, port int, username string, password string, hash string, kerberos bool, cCachePath string, dc string, ldaps bool) *LDAPConnection {
	var l string
	if ldaps {
		l = fmt.Sprintf("%s:%d", host, 636)
	} else {
		l = fmt.Sprintf("%s:%d", host, 389)
	}
	return &LDAPConnection{
		Domain:      domain,
		Host:        host,
		Username:    username,
		Password:    password,
		Hash:        hash,
		Kerberos:    kerberos,
		CCachePath:  cCachePath,
		DC:          dc,
		TLS:         ldaps,
		ldapAddress: l,
	}
}

// Connect connects to the LDAP server
func (l *LDAPConnection) Login() error {
	var err error

	if l.TLS {
		l.Conn, err = ldap.DialTLS("tcp", l.ldapAddress, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return err
		}
	} else {
		l.Conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s", l.ldapAddress))
		if err != nil {
			return err
		}
	}

	if l.Kerberos {
		var cl *client.Client
		spn := fmt.Sprintf("LDAP/%s", l.Host)
		cl = gokrb5.GetKerberosClientEx(l.Domain, l.DC, l.Username, l.Password, l.Hash, l.CCachePath, "", 0)
		hasST, spnMatch := cl.SessionHasSPN(spn)
		hasTGT, _ := cl.SessionHasSPN("krbtgt/" + l.Domain)
		if !hasST {
			if !hasTGT {
				err = cl.Login()
				if err != nil {
					return err
				}
			}
			_, _, err = cl.GetServiceTicket(spn)
			if err != nil {
				return err
			}
		}
		if spnMatch != spn && spnMatch != "" {
			spn = spnMatch
		}
		_, err = l.Conn.GSSAPICCBindCCache(cl, spn)
		if err != nil {
			return err
		}

	} else {
		// u := l.Username + "@" + l.Domain
		if l.Password != "" {
			err = l.Conn.NTLMBind(l.Domain, l.Username, l.Password)
			// err = l.Conn.Bind(u, l.Password)
			if err != nil {
				return err
			}
		} else if l.Hash != "" {
			err = l.Conn.NTLMBindWithHash(l.Domain, l.Username, l.Hash)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (l *LDAPConnection) Close() {
	l.Conn.Close()
}
