package qpack

import "errors"

// DecoderErrorKind identifies the protocol category of a QPACK decoding error.
type DecoderErrorKind uint8

const (
	// DecoderErrorMalformed identifies malformed or truncated field-section data.
	DecoderErrorMalformed DecoderErrorKind = iota + 1
	// DecoderErrorValueTooLarge identifies a value the implementation cannot decode.
	DecoderErrorValueTooLarge
	// DecoderErrorInvalidReference identifies an invalid static or dynamic table reference.
	DecoderErrorInvalidReference
	// DecoderErrorInvalidRequiredInsertCount identifies an invalid Required Insert Count.
	DecoderErrorInvalidRequiredInsertCount
	// DecoderErrorInvalidBase identifies an invalid Delta Base.
	DecoderErrorInvalidBase
)

// DecoderError wraps a QPACK decoding failure with a stable classification.
type DecoderError struct {
	Kind DecoderErrorKind
	Err  error
}

func (e *DecoderError) Error() string {
	if e == nil || e.Err == nil {
		return "qpack decoding error"
	}
	return e.Err.Error()
}

// Unwrap returns the underlying decoding error.
func (e *DecoderError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func classifyDecoderError(err error) error {
	if err == nil {
		return nil
	}
	var decoderErr *DecoderError
	if errors.As(err, &decoderErr) {
		return err
	}
	kind := DecoderErrorMalformed
	switch {
	case errors.Is(err, errVarintOverflow):
		kind = DecoderErrorValueTooLarge
	case errors.Is(err, errNoDynamicTable):
		kind = DecoderErrorInvalidReference
	case errors.Is(err, errInvalidRequiredInsertCount):
		kind = DecoderErrorInvalidRequiredInsertCount
	case errors.Is(err, errInvalidBase):
		kind = DecoderErrorInvalidBase
	default:
		var invalidIndex invalidIndexError
		if errors.As(err, &invalidIndex) {
			kind = DecoderErrorInvalidReference
		}
	}
	return &DecoderError{Kind: kind, Err: err}
}
