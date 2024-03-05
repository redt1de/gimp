package smb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/redt1de/dbg"
	"github.com/redt1de/gimp/goimpacket/go-smb/smb/crypto/ccm"
	"github.com/redt1de/gimp/goimpacket/go-smb/smb/crypto/cmac"
	"github.com/redt1de/gimp/goimpacket/go-smb/smb/encoder"
)

var dlog = dbg.Get("smb/session")

func (c *Connection) SessionSetupKerberos() error {
	spnegoClient := newSpnegoClient([]Initiator{c.options.Initiator})
	log.Debugln("Sending SessionSetup1 request")
	ssreq, err := c.NewSessionSetup1Req(spnegoClient)
	if err != nil {
		log.Errorln(err)
		return err
	}
	ssres, err := NewSessionSetup1Res()
	if err != nil {
		log.Errorln(err)
		return err
	}
	ssreq.Credits = 127
	ssreq.MessageID = 1

	rr, err := c.send(ssreq)
	if err != nil {
		log.Errorln(err)
		return err
	}
	ssresbuf, err := c.recv(rr)
	if err != nil {
		log.Errorln(err)
		return err
	}

	log.Debugln("Unmarshalling SessionSetup1 response")
	if err := encoder.Unmarshal(ssresbuf, &ssres); err != nil {
		log.Errorln(err)
		return err
	}

	if ssres.Header.Status != StatusMoreProcessingRequired && ssres.Header.Status != StatusOk {
		status, found := StatusMap[ssres.Header.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for SessionSetup1 response: 0x%x\n", ssres.Header.Status)
			log.Errorln(err)
			return err
		}
		log.Debugf("NT Status Error: %v\n", status)
		return status
	}

	c.sessionID = ssres.Header.SessionID
	if c.IsSigningRequired.Load() {
		if ssres.Flags&SessionFlagIsGuest != 0 {
			err = fmt.Errorf("guest account doesn't support signing")
			log.Errorln(err)
			return err
		} else if ssres.Flags&SessionFlagIsNull != 0 {
			err = fmt.Errorf("anonymous account doesn't support signing")
			log.Errorln(err)
			return err
		}
	}

	c.sessionFlags = ssres.Flags
	if c.Session.options.DisableEncryption {
		c.sessionFlags &= ^SessionFlagEncryptData
	} else if c.supportsEncryption {
		c.sessionFlags |= SessionFlagEncryptData
	}

	switch c.dialect {
	case DialectSmb_3_1_1:
		c.Session.preauthIntegrityHashValue = c.preauthIntegrityHashValue
		switch c.preauthIntegrityHashId {
		case SHA512:
			h := sha512.New()
			h.Write(c.Session.preauthIntegrityHashValue[:])
			h.Write(rr.pkt)
			h.Sum(c.Session.preauthIntegrityHashValue[:0])

			if ssres.Header.Status == StatusMoreProcessingRequired {
				h.Reset()
				h.Write(c.Session.preauthIntegrityHashValue[:])
				h.Write(ssresbuf)
				h.Sum(c.Session.preauthIntegrityHashValue[:0])
			}
		}
	}

	if c.options.Initiator.isNullSession() {
		// Anonymous auth
		c.sessionFlags |= SessionFlagIsNull
		c.sessionFlags &= ^SessionFlagEncryptData
	}

	off := ssres.SecurityBufferOffset
	ln := ssres.SecurityBufferLength
	_, err = spnegoClient.acceptSecContext(ssresbuf[off : off+ln])
	if err != nil {
		panic(err)
	}

	// Retrieve the full username used in the authentication attempt
	// <domain\username> or just <username> if domain component is empty
	c.Session.authUsername = c.options.Initiator.getUsername()

	// Check if we authenticated as guest or with a null session. If so, disable signing and encryption
	if ((ssres.Flags & SessionFlagIsGuest) == SessionFlagIsGuest) || ((ssres.Flags & SessionFlagIsNull) == SessionFlagIsNull) {
		c.IsSigningRequired.Store(false)
		c.options.DisableEncryption = true
		c.sessionFlags = ssres.Flags              //NOTE Replace all sessionFlags here?
		c.sessionFlags &= ^SessionFlagEncryptData // Make sure encryption is disabled

		if (ssres.Flags & SessionFlagIsGuest) == SessionFlagIsGuest {
			c.sessionFlags |= SessionFlagIsGuest
		} else {
			c.sessionFlags |= SessionFlagIsNull
		}
	}

	c.IsAuthenticated = true

	// Handle signing and encryption options
	if c.sessionFlags&(SessionFlagIsGuest|SessionFlagIsNull) == 0 {
		sessionKey := spnegoClient.sessionKey()

		switch c.dialect {
		case DialectSmb_2_0_2, DialectSmb_2_1:
			dlog.Debugln("Dialect is: DialectSmb_2_0_2 or DialectSmb_2_1")
			if !c.IsSigningDisabled {
				c.Session.signer = hmac.New(sha256.New, sessionKey)
				c.Session.verifier = hmac.New(sha256.New, sessionKey)
			}
		case DialectSmb_3_1_1:
			dlog.Debugln("Dialect is: DialectSmb_3_1_1")
			// switch c.preauthIntegrityHashId {
			// case SHA512:
			// h := sha512.New()
			// h.Write(c.Session.preauthIntegrityHashValue[:])
			// h.Write(rr.pkt)
			// h.Sum(c.Session.preauthIntegrityHashValue[:0])
			// }

			// SMB 3.1.1 requires either signing or encryption of requests, so can't disable signing.
			// Signingkey is always 128bit
			signingKey := kdf(sessionKey, []byte("SMBSigningKey\x00"), c.Session.preauthIntegrityHashValue[:], 128)

			if os.Getenv("SMB_LOGKEYS") == "1" {
				sess := binary.LittleEndian.AppendUint64(nil, c.sessionID)
				dlog.Debugf("Exported session secrets: %x,%x,,\n", sess, sessionKey)
			}

			switch c.signingId {
			case AES_CMAC:
				c.Session.signer, err = cmac.New(signingKey)
				if err != nil {
					log.Errorln(err)
					return err
				}
				c.Session.verifier, err = cmac.New(signingKey)
				if err != nil {
					log.Errorln(err)
					return err
				}
			default:
				err = fmt.Errorf("Unknown signing algorithm (%d) not implemented", c.signingId)
				log.Errorln(err)
				return err
			}

			// Determine size of L variable for the KDF
			var l uint32
			switch c.cipherId {
			case AES128GCM:
				l = 128
			case AES128CCM:
				l = 128
			case AES256CCM:
				l = 256
			case AES256GCM:
				l = 256
			default:
				err = fmt.Errorf("Cipher algorithm (%d) not implemented", c.cipherId)
				log.Errorln(err)
				return err
			}

			encryptionKey := kdf(sessionKey, []byte("SMBC2SCipherKey\x00"), c.Session.preauthIntegrityHashValue[:], l)
			decryptionKey := kdf(sessionKey, []byte("SMBS2CCipherKey\x00"), c.Session.preauthIntegrityHashValue[:], l)

			switch c.cipherId {
			case AES128GCM, AES256GCM:
				dlog.Debugln("Cipher is: AES128GCM or AES256GCM")
				ciph, err := aes.NewCipher(encryptionKey)
				if err != nil {
					log.Errorln(err)
					return err
				}
				c.Session.encrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
				if err != nil {
					log.Errorln(err)
					return err
				}

				ciph, err = aes.NewCipher(decryptionKey)
				if err != nil {
					log.Errorln(err)
					return err
				}
				c.Session.decrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
				if err != nil {
					log.Errorln(err)
					return err
				}
				log.Debugln("Initialized encrypter and decrypter with GCM")
			case AES128CCM, AES256CCM:
				dlog.Debugln("Cipher is: AES128CCM or AES256CCM")
				ciph, err := aes.NewCipher(encryptionKey)
				if err != nil {
					log.Errorln(err)
					return err
				}
				c.Session.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
				ciph, err = aes.NewCipher(decryptionKey)
				if err != nil {
					log.Errorln(err)
					return err
				}
				c.Session.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
				log.Debugln("Initialized encrypter and decrypter with CCM")
			default:
				err = fmt.Errorf("Cipher algorithm (%d) not implemented", c.cipherId)
				log.Errorln(err)
				return err
			}
		}
	}

	log.Debugln("Completed NegotiateProtocol and SessionSetup")

	c.enableSession()

	return nil
}
