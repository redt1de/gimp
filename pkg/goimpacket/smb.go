package goimpacket

import (
	"encoding/hex"
	"fmt"
	"net"

	"github.com/redt1de/gimp/pkg/go-smb2"
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
	SmbConn *smb2.Session
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

// Connect connects to the LDAP server
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

		conn, err := net.Dial("tcp", fmt.Sprintf("%s:445", l.Host))
		if err != nil {
			conn.Close()
			return err
		}

		d := &smb2.Dialer{
			Initiator: &smb2.KerberosInitiator{
				SPN:    spn,
				Client: cl,
				User:   cl.Credentials.CName(),
			},
		}

		l.SmbConn, err = d.Dial(conn)
		if err != nil {
			conn.Close()
			return err
		}

	} else {
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:445", l.Host))

		if err != nil {
			conn.Close()
			return err
		}
		d := &smb2.Dialer{
			Negotiator: smb2.Negotiator{
				RequireMessageSigning: false,
				SpecifiedDialect:      0x302,
			},
			Initiator: &smb2.NTLMInitiator{
				Domain:   l.Domain,
				User:     l.Username,
				Password: l.Password,
			},
		}

		if l.Hash != "" {
			hashhex, err := hex.DecodeString(l.Hash)
			if err != nil {
				return err
			}
			d = &smb2.Dialer{
				Initiator: &smb2.NTLMInitiator{
					Domain: l.Domain,
					User:   l.Username,
					Hash:   hashhex,
				},
			}

		}

		l.SmbConn, err = d.Dial(conn)
		if err != nil {
			conn.Close()
			return err
		}

	}

	return nil
}

func (l *SMBConnection) Close() {
	l.SmbConn.Logoff()
}
