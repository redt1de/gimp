package goimpacket

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/redt1de/dbg"
	"github.com/redt1de/gimp/goimpacket/gokrb5"
	"github.com/redt1de/gimp/goimpacket/gokrb5/client"
	"github.com/redt1de/gimp/goimpacket/ldap"
)

var ldlog = dbg.Get("goimpacket/ldap")

type LDAPConnection struct {
	Domain      string
	Host        string
	Username    string
	Password    string
	Hash        string
	Kerberos    bool
	CCachePath  string
	DC          string
	TLS         bool
	Conn        *ldap.Conn
	ldapAddress string
	BaseDN      string
}

// NewLDAPConnection creates a new LDAPConnection object
func NewLDAPConnection(ac *ADAccount, at *ADTarget, ldaps bool) *LDAPConnection {
	var l string
	if ldaps {
		l = fmt.Sprintf("%s:%d", at.Host, 636)
	} else {
		l = fmt.Sprintf("%s:%d", at.Host, 389)
	}
	return &LDAPConnection{
		Domain:      ac.Domain,
		Host:        at.Host,
		Username:    ac.Username,
		Password:    ac.Password,
		Hash:        ac.Hash,
		Kerberos:    ac.Kerberos,
		CCachePath:  ac.CCachePath,
		DC:          ac.DC,
		TLS:         ldaps,
		ldapAddress: l,
		BaseDN:      "",
	}
}

// Connect connects to the LDAP server
func (l *LDAPConnection) Login() error {
	var err error

	if l.TLS {
		cf := &tls.Config{InsecureSkipVerify: true}
		if os.Getenv("LDAP_LOGKEYS") == "1" {
			ldlog.Debugf("Exporting LDAP TLS keys to /tmp/ldap_keys\n")
			f, err := os.OpenFile("/tmp/ldap_keys", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				panic(err)
			}
			defer f.Close()
			cf.KeyLogWriter = f
		}

		l.Conn, err = ldap.DialTLS("tcp", l.ldapAddress, cf)
		if err != nil {
			return err
		}
		ldlog.Debugf("Dialing (TLS): %s\n", l.ldapAddress)
	} else {
		l.Conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s", l.ldapAddress))
		if err != nil {
			return err
		}
		ldlog.Debugf("Dialing: %s\n", fmt.Sprintf("ldap://%s", l.ldapAddress))
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
		ldlog.Debugln("Binding ...")
		_, err = l.Conn.GSSAPICCBindCCache(cl, spn)
		if err != nil {
			return err
		}
		ldlog.Debugln("Bound")

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

	l.BaseDN, err = l.baseDN()
	if err != nil {
		return err
	}
	return nil
}

func (l *LDAPConnection) Close() {
	l.Conn.Close()
}

func (l *LDAPConnection) baseDN() (string, error) {
	sr, err := l.Conn.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	))
	if err != nil {
		return "", err
	}
	return sr.Entries[0].GetAttributeValue("defaultNamingContext"), nil
}
