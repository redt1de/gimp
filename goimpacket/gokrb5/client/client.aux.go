package client

import (
	"fmt"
	"strings"

	"github.com/redt1de/gimp/goimpacket/gokrb5/config"
	"github.com/redt1de/gimp/goimpacket/gokrb5/credentials"
	"github.com/redt1de/gimp/goimpacket/gokrb5/messages"
)

// NewFromCCacheEx creates a client from a CCACHE that includes credentials for all SPNs in the cache. This works to create a client from an ST without a TGT.
func NewFromCCacheEx(c *credentials.CCache, krb5conf *config.Config, settings ...func(*Settings)) (*Client, error) {
	cl := &Client{
		Credentials: c.GetClientCredentials(),
		Config:      krb5conf,
		settings:    NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
		},
		cache: NewCache(),
	}

	for i := range c.Credentials {
		cred := c.Credentials[i]

		var tgt messages.Ticket
		err := tgt.Unmarshal(cred.Ticket)
		if err != nil {
			return cl, fmt.Errorf("TGT bytes in cache are not valid: %v", err)
		}
		cl.sessions.Entries[c.DefaultPrincipal.Realm] = &session{
			realm:      c.DefaultPrincipal.Realm,
			authTime:   cred.AuthTime,
			endTime:    cred.EndTime,
			renewTill:  cred.RenewTill,
			tgt:        tgt,
			sessionKey: cred.Key,
		}
		for _, cred := range c.GetEntries() {
			var tkt messages.Ticket
			err = tkt.Unmarshal(cred.Ticket)
			if err != nil {
				return cl, fmt.Errorf("cache entry ticket bytes are not valid: %v", err)
			}
			cl.cache.addEntry(
				tkt,
				cred.AuthTime,
				cred.StartTime,
				cred.EndTime,
				cred.RenewTill,
				cred.Key,
			)
		}
	}
	return cl, nil
}

// GetSessionSPNs returns the SPNs for which the client has sessions.
func (cl *Client) GetSessionSPNs() []string {
	var spns []string
	for _, cred := range cl.cache.Entries {
		spns = append(spns, cred.SPN)
	}
	return spns
}

// SessionHasSPN checks if the client has a session for the specified SPN, returns bool and the SPN if found. The SPN is returned in the case as it is in the cache.
func (cl *Client) SessionHasSPN(spn string) (bool, string) {
	for _, cred := range cl.cache.Entries {
		if strings.EqualFold(cred.SPN, spn) {
			return true, cred.SPN
		}

	}
	return false, ""
}
