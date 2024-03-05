package goimpacket

import (
	"fmt"

	"github.com/redt1de/gimp/pkg/go-smb/smb"
	"github.com/redt1de/gimp/pkg/gokrb5"
	"github.com/redt1de/gimp/pkg/gokrb5/client"
)

type SMBConnection struct {
	Domain     string
	Host       string
	Port       int
	Username   string
	Password   string
	Hash       string
	Kerberos   bool
	CCachePath string
	DC         string
	// conn       *net.Conn
	SmbSession  *smb.Connection
	IsConnected bool
}

// NewLDAPConnection creates a new LDAPConnection object
func NewSMBConnection(domain string, host string, username string, password string, hash string, kerberos bool, cCachePath string, dc string) *SMBConnection {
	return &SMBConnection{
		Domain:     domain,
		Host:       host,
		Username:   username,
		Password:   password,
		Hash:       hash,
		Kerberos:   kerberos,
		CCachePath: cCachePath,
		DC:         dc,
	}
}

// Connect connects to the SMB server
func (l *SMBConnection) Login() error {
	var err error

	if l.Kerberos {
		var cl *client.Client
		spn := fmt.Sprintf("CIFS/%s", l.Host)

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

		ki := smb.KerberosInitiator{
			User:               cl.Credentials.CName(),
			TargetSPN:          spn,
			Client:             cl,
			DisableSigning:     false,
			EncryptionDisabled: false,
		}

		options := smb.Options{
			Host:      l.Host,
			Port:      445,
			Initiator: &ki,
		}
		l.SmbSession, err = smb.NewConnection(options)
		if err != nil {
			fmt.Println(err)
			return err
		}
		defer l.SmbSession.Close()

	} else {
		options := smb.Options{
			Host: l.Host,
			Port: 445,
			Initiator: &smb.NTLMInitiator{
				User:     l.Username,
				Password: l.Password,
				Domain:   l.Domain,
				// TODO: add hash support
				DisableSigning:     true,
				EncryptionDisabled: true,
			},
		}
		l.SmbSession, err = smb.NewConnection(options)
		if err != nil {
			fmt.Println(err)
			return err
		}
		defer l.SmbSession.Close()

	}
	l.IsConnected = true

	return nil
}

func (l *SMBConnection) Close() {
	l.SmbSession.Close()
}
