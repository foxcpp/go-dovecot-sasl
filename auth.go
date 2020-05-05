package dovecotsasl

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
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
	RequestID string
	Code      FailCode
	Reason    string
}

func (af AuthFail) Error() string {
	if af.Reason != "" {
		return fmt.Sprintf("dovecotsasl: authentication failed: %s (code=%s)", af.Reason, string(af.Code))
	}
	return fmt.Sprintf("dovecotsasl: authentication failed (code=%s)", string(af.Code))
}

func parseFail(params []string) AuthFail {
	if len(params) == 0 {
		return AuthFail{}
	}

	af := AuthFail{
		RequestID: params[0],
	}
	for _, p := range params[1:] {
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
	params := make([]string, 0, 3)
	params = append(params, af.RequestID)
	if af.Reason != "" && !strings.ContainsAny(af.Reason, "\t\n") {
		params = append(params, "reason="+af.Reason)
	}
	if af.Code != "" && !strings.ContainsAny(string(af.Code), "\t\n") {
		params = append(params, "code="+string(af.Code))
	}
	return params
}

type AuthReq struct {
	RequestID string
	Mechanism string
	Service   string

	LocalIP   net.IP
	LocalPort uint16

	RemoteIP   net.IP
	RemotePort uint16

	Secured         bool
	ValidClientCert bool
	NoPenalty       bool
	CertUsername    bool

	IR []byte
}

func parseAuthReq(params []string) (*AuthReq, error) {
	if len(params) < 3 {
		return nil, fmt.Errorf("dovecotsasl: malformed request: not enough params")
	}

	req := AuthReq{
		RequestID: params[0],
		Mechanism: params[1],
	}

	for _, p := range params[2:] {
		parts := strings.SplitN(p, "=", 2)
		switch parts[0] {
		case "resp":
			if len(parts) != 2 {
				return nil, fmt.Errorf("dovecotsasl: missing value for resp")
			}
			resp, err := base64.StdEncoding.DecodeString(parts[1])
			if err != nil {
				return nil, fmt.Errorf("dovecotsasl: malformed initial response: %v", err)
			}
			req.IR = resp
		case "service":
			req.Service = parts[1]
		case "secured":
			req.Secured = true
		case "valid-client-cert":
			req.ValidClientCert = true
		case "no-penalty":
			req.NoPenalty = true
		case "cert_username":
			req.CertUsername = true
		case "lip":
			if len(parts) != 2 {
				return nil, fmt.Errorf("dovecotsasl: missing value for lip")
			}
			req.LocalIP = net.ParseIP(parts[1])
			if req.LocalIP == nil {
				return nil, fmt.Errorf("dovecotsasl: malformed lip: %v", parts[1])
			}
		case "lport":
			if len(parts) != 2 {
				return nil, fmt.Errorf("dovecotsasl: missing value for lport")
			}
			val, err := strconv.ParseUint(parts[1], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("dovecotsasl: malformed lport: %v", parts[1])
			}
			req.LocalPort = uint16(val)
		case "rip":
			if len(parts) != 2 {
				return nil, fmt.Errorf("dovecotsasl: missing value for rip")
			}
			req.RemoteIP = net.ParseIP(parts[1])
			if req.RemoteIP == nil {
				return nil, fmt.Errorf("dovecotsasl: malformed rip: %v", parts[1])
			}
		case "rport":
			if len(parts) != 2 {
				return nil, fmt.Errorf("dovecotsasl: missing value for rport")
			}
			val, err := strconv.ParseUint(parts[1], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("dovecotsasl: malformed rport: %v", parts[1])
			}
			req.RemotePort = uint16(val)
		}
	}

	return &req, nil
}
