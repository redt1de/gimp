package goimpacket

import (
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/redt1de/gimp/goimpacket/util"
)

type ADTarget struct {
	Domain string
	Host   string
	Port   int
}

type ADAccount struct {
	Domain     string
	Username   string
	Password   string
	Hash       string
	Kerberos   bool
	CCachePath string
	DC         string
}

func NewADTarget(domain, host string, port int) *ADTarget {
	return &ADTarget{
		Domain: domain,
		Host:   host,
		Port:   port,
	}
}

func NewADTargetFromString(target string) (*ADTarget, error) {
	domain, _, _, host := util.ParseTargetString(target)
	port := 0
	// if err != nil {
	// 	return nil, err
	// }
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
		port, _ = strconv.Atoi(strings.Split(host, ":")[1])
	}
	return NewADTarget(domain, host, port), nil
}

func NewADAccount(domain, username, password, hash string, kerberos bool, ccachePath, dc string) *ADAccount {
	return &ADAccount{
		Domain:     domain,
		Username:   username,
		Password:   password,
		Hash:       hash,
		Kerberos:   kerberos,
		CCachePath: ccachePath,
		DC:         dc,
	}
}

func NewADAccountFromString(target string) (*ADAccount, error) {
	domain, username, password, _ := util.ParseTargetString(target)
	return NewADAccount(domain, username, password, "", false, "", ""), nil
}

func (a *ADAccount) HashBytes() []byte {
	if a.Hash == "" {
		return nil
	}
	b, err := hex.DecodeString(strings.Replace(a.Hash, ":", "", -1))
	if err != nil {
		return nil
	}
	return b
}

func (a *ADAccount) GetDC() {

}
