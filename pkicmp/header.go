package pkicmp

import "encoding/asn1"

// CertProfile extracts the first certProfile name from the generalInfo header field.
// RFC 9810 §5.1.1.4: id-it-certProfile carries a SEQUENCE OF UTF8String.
// Returns empty string if not present.
func (h *PKIHeader) CertProfile() string {
	for _, itv := range h.GeneralInfo {
		if itv.InfoType.Equal(OIDCertProfile) {
			var profiles []string
			if _, err := asn1.Unmarshal(itv.InfoValue, &profiles); err == nil && len(profiles) > 0 {
				return profiles[0]
			}
		}
	}
	return ""
}
