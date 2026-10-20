package smapi

import (
	"strconv"
	"time"
)

// Timestamp is a time on the wire, where the AWS JSON protocol represents one
// as epoch seconds with a fractional part rather than as a string.
type Timestamp time.Time

// MarshalJSON encodes the timestamp as epoch seconds to millisecond
// precision, which is what the AWS SDKs parse.
func (t Timestamp) MarshalJSON() ([]byte, error) {
	millis := time.Time(t).UnixMilli()
	return strconv.AppendFloat(nil, float64(millis)/1e3, 'f', -1, 64), nil
}

// Stamp returns ts as a wire timestamp, or nil when it is the zero time, so
// callers can leave unset dates out of a response.
func Stamp(ts time.Time) *Timestamp {
	if ts.IsZero() {
		return nil
	}
	stamp := Timestamp(ts)
	return &stamp
}
