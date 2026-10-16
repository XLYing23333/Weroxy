package sqlite

import (
	"errors"
	"math"
	"time"
)

var ErrPolicyInvalid = errors.New("invalid numeric policy")

// Zero remains a denial and nil remains inheritance. Duration arithmetic must
// not overflow even when an API caller bypasses the Web input checks.
func (v PolicyValues) Valid() bool {
	for _, value := range []*int{v.MaxPending, v.MaxPerIP, v.RatePerSec, v.Burst, v.IdleSec, v.ConnectSec, v.WaitSec, v.Bandwidth} {
		if value != nil && *value < 0 {
			return false
		}
	}
	for _, value := range []*int{v.IdleSec, v.ConnectSec, v.WaitSec} {
		if value != nil && int64(*value) > math.MaxInt64/int64(time.Second) {
			return false
		}
	}
	return true
}
