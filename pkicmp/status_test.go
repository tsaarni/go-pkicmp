package pkicmp

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

// RFC 9810 §5.2.3 (PKIStatus mapping tests)
func TestPKIStatusString(t *testing.T) {
	t.Run("Accepted", func(t *testing.T) {
		assert.Equal(t, "accepted", StatusAccepted.String())
	})
	t.Run("GrantedWithMods", func(t *testing.T) {
		assert.Equal(t, "grantedWithMods", StatusGrantedWithMods.String())
	})
	t.Run("Rejection", func(t *testing.T) {
		assert.Equal(t, "rejection", StatusRejection.String())
	})
	t.Run("Waiting", func(t *testing.T) {
		assert.Equal(t, "waiting", StatusWaiting.String())
	})
	t.Run("RevocationWarning", func(t *testing.T) {
		assert.Equal(t, "revocationWarning", StatusRevocationWarning.String())
	})
	t.Run("RevocationNotification", func(t *testing.T) {
		assert.Equal(t, "revocationNotification", StatusRevocationNotification.String())
	})
	t.Run("KeyUpdateWarning", func(t *testing.T) {
		assert.Equal(t, "keyUpdateWarning", StatusKeyUpdateWarning.String())
	})
	t.Run("Unknown", func(t *testing.T) {
		assert.Equal(t, "unknown(99)", PKIStatus(99).String())
	})
}

// RFC 9810 §5.2.3 (PKIFailureInfo mapping tests)
func TestPKIFailureInfoString(t *testing.T) {
	t.Run("Single", func(t *testing.T) {
		assert.Equal(t, "badAlg", FailBadAlg.String())
	})
	t.Run("Multiple", func(t *testing.T) {
		combined := FailBadAlg | FailBadRequest
		assert.Contains(t, combined.String(), "badAlg")
		assert.Contains(t, combined.String(), "badRequest")
	})
	t.Run("UnknownBit", func(t *testing.T) {
		unknown := PKIFailureInfo(1 << 31)
		assert.NotEmpty(t, unknown.String())
	})
	t.Run("AllKnown", func(t *testing.T) {
		// Just ensure it doesn't panic and returns something for a few known ones
		s := (FailBadAlg | FailDuplicateCertReq).String()
		assert.Contains(t, s, "badAlg")
		assert.Contains(t, s, "duplicateCertReq")
	})
}

// RFC 9810 §5.2.3 (PKIStatusInfo to error conversion)
func TestPKIStatusInfoAsError(t *testing.T) {
	t.Run("Accepted", func(t *testing.T) {
		si := PKIStatusInfo{Status: StatusAccepted}
		assert.NoError(t, si.AsError())
	})
	t.Run("GrantedWithMods", func(t *testing.T) {
		si := PKIStatusInfo{Status: StatusGrantedWithMods}
		assert.NoError(t, si.AsError())
	})
	t.Run("Waiting", func(t *testing.T) {
		si := PKIStatusInfo{Status: StatusWaiting}
		assert.Equal(t, ErrWaiting, si.AsError())
	})
	t.Run("Rejection", func(t *testing.T) {
		si := PKIStatusInfo{
			Status:       StatusRejection,
			StatusString: []string{"test error"},
			FailInfo:     FailBadAlg,
		}
		err := si.AsError()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status rejection")
		assert.Contains(t, err.Error(), "failInfo: badAlg")
		assert.Contains(t, err.Error(), "details: test error")
	})
}

func TestHasFailure(t *testing.T) {
	errSingle := &PKIStatusError{
		Status:   StatusRejection,
		FailInfo: FailBadAlg,
	}

	errMulti := &PKIStatusError{
		Status:   StatusRejection,
		FailInfo: FailBadAlg | FailBadTime | FailBadRequest,
	}

	t.Run("SingleBit", func(t *testing.T) {
		assert.True(t, HasFailure(errSingle, FailBadAlg))
		assert.False(t, HasFailure(errSingle, FailBadTime))
	})

	t.Run("MultipleBits", func(t *testing.T) {
		assert.True(t, HasFailure(errMulti, FailBadAlg))
		assert.True(t, HasFailure(errMulti, FailBadTime))
		assert.True(t, HasFailure(errMulti, FailBadRequest))
		assert.False(t, HasFailure(errMulti, FailBadCertId))
	})

	t.Run("CombinationMask", func(t *testing.T) {
		// errSingle has only FailBadAlg
		// Checking for (FailBadAlg OR FailBadTime) should be true.
		assert.True(t, HasFailure(errSingle, FailBadAlg|FailBadTime))

		// errMulti has (FailBadAlg | FailBadTime | FailBadRequest)
		// Checking for (FailBadCertId OR FailBadDataFormat) should be false.
		assert.False(t, HasFailure(errMulti, FailBadCertId|FailBadDataFormat))
	})

	t.Run("WrappedError", func(t *testing.T) {
		wrapped := fmt.Errorf("outer: %w", errSingle)
		assert.True(t, HasFailure(wrapped, FailBadAlg))
	})

	t.Run("OtherError", func(t *testing.T) {
		assert.False(t, HasFailure(errors.New("not a pki error"), FailBadAlg))
		assert.False(t, HasFailure(nil, FailBadAlg))
	})
}

// RFC 9810 §5.2.3 (PKIStatusInfo ASN.1 tests)
func TestPKIStatusInfoASN1(t *testing.T) {
	t.Run("MarshalAndUnmarshal", func(t *testing.T) {
		si := PKIStatusInfo{
			Status:       StatusRejection,
			StatusString: []string{"bad", "request"},
			FailInfo:     FailBadAlg,
		}

		var b cryptobyte.Builder
		si.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, err := b.Bytes()
		require.NoError(t, err)

		var unmarshaled PKIStatusInfo
		s := cryptobyte.String(marshaled)
		err = unmarshaled.unmarshal(&s)
		require.NoError(t, err)

		assert.Equal(t, si.Status, unmarshaled.Status)
		assert.Equal(t, si.StatusString, unmarshaled.StatusString)
		assert.Equal(t, si.FailInfo, unmarshaled.FailInfo)
	})

	t.Run("UnmarshalInvalid", func(t *testing.T) {
		s := cryptobyte.String([]byte{0x00}) // Not a sequence
		var unmarshaled PKIStatusInfo
		err := unmarshaled.unmarshal(&s)
		assert.Error(t, err)
	})
}

// RFC 9810 §5.3.21 (ErrorMsgContent ASN.1 tests)
func TestErrorMsgContentASN1(t *testing.T) {
	e := &ErrorMsgContent{
		PKIStatusInfo: PKIStatusInfo{
			Status: StatusRejection,
		},
		ErrorCode:    123,
		ErrorDetails: []string{"detailed error"},
	}

	var b cryptobyte.Builder
	e.marshal(&MarshalContext{MinRequiredPVNO: PVNO2}, &b)
	marshaled, err := b.Bytes()
	require.NoError(t, err)

	unmarshaled := &ErrorMsgContent{}
	s := cryptobyte.String(marshaled)
	err = unmarshaled.unmarshal(&s)
	require.NoError(t, err)

	assert.Equal(t, e.PKIStatusInfo.Status, unmarshaled.PKIStatusInfo.Status)
	assert.Equal(t, e.ErrorCode, unmarshaled.ErrorCode)
	assert.Equal(t, e.ErrorDetails, unmarshaled.ErrorDetails)
}
