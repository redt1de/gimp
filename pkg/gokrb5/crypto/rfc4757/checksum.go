package rfc4757

import (
	"crypto/hmac"
	"crypto/md5"
)

// Checksum returns a hash of the data in accordance with RFC 4757
func Checksum(key []byte, usage uint32, data []byte) ([]byte, error) {
	// Create hashing key
	s := append([]byte(`signaturekey`), byte(0x00)) //includes zero octet at end
	mac := hmac.New(md5.New, key)
	mac.Write(s)
	Ksign := mac.Sum(nil)

	// Format data
	h := md5.New()
	h.Write(UsageToMSMsgType(usage))
	h.Write(data)
	tmp := h.Sum(nil)

	// Generate HMAC
	mac = hmac.New(md5.New, Ksign)
	mac.Write(tmp)
	return mac.Sum(nil), nil
}

// HMAC returns a keyed MD5 checksum of the data
func HMAC(key []byte, data []byte) []byte {
	mac := hmac.New(md5.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
