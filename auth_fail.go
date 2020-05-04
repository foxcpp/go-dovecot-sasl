package dovecotsasl

import (
	"fmt"
	"strings"
)

type FailCode string

const (
	TempFail     = "temp_fail"
	AuthzFail    = "authz_fail"
	UserDisabled = "user_disabled"
	PassExpired  = "pass_expired"
)

type AuthFail struct {
	Code   FailCode
	Reason string
}

func (af AuthFail) Error() string {
	if af.Reason != "" {
		return fmt.Sprintf("dovecotsasl: authentication failed: %s (code=%s)", af.Reason, string(af.Code))
	}
	return fmt.Sprintf("dovecotsasl: authentication failed (code=%s)", string(af.Code))
}

func parseFail(optParams []string) AuthFail {
	af := AuthFail{}
	for _, p := range optParams {
		parts := strings.SplitN(p, "=", 2)
		switch parts[0] {
		case "reason":
			if len(parts) < 2 {
				// Skip empty reason.
				continue
			}
			af.Reason = parts[1]
		case "code":
			if len(parts) < 2 {
				// Skip empty reason.
				continue
			}
			af.Code = FailCode(parts[1])

			// Legacy, 2.2 codes.
		case "temp":
			af.Code = TempFail
		case "authz":
			af.Code = AuthzFail
		case "user_disabled":
			af.Code = UserDisabled
		case "pass_expired":
			af.Code = PassExpired
		}
	}
	return af
}

func (af AuthFail) format() []string {
	params := make([]string, 0, 2)
	if af.Reason != "" && !strings.ContainsAny(af.Reason, "\t\n") {
		params = append(params, "reason="+af.Reason)
	}
	if af.Code != "" && !strings.ContainsAny(string(af.Code), "\t\n") {
		params = append(params, "code="+string(af.Code))
	}
	return params
}
