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

type AuthOK struct {
	RequestID string
	UserID    string
	Extra     map[string]string
}

func parseOk(params []string) AuthOK {
	if len(params) == 0 {
		return AuthOK{}
	}

	ao := AuthOK{
		RequestID: params[0],
		Extra:     make(map[string]string),
	}
	for _, p := range params[1:] {
		parts := strings.SplitN(p, "=", 2)
		switch parts[0] {
		case "userid":
			ao.UserID = parts[1]
		default:
			ao.Extra[parts[0]] = parts[1]
		}
	}
	return ao
}

func (ao AuthOK) format() []string {
	params := make([]string, 0, 3)
	params = append(params, ao.RequestID)
	if ao.UserID != "" && !strings.ContainsAny(ao.UserID, "=\t\n") {
		params = append(params, "userid="+ao.UserID)
	}
	for k, v := range ao.Extra {
		if !strings.ContainsAny(k, "=\t\n") || !strings.ContainsAny(v, "=\t\n") {
			continue
		}
		params = append(params, k+"="+v)
	}
	return params
}

type SecuredMethod string

var (
	SecuredNone      SecuredMethod = ""
	SecuredLocalhost SecuredMethod = "localhost"
	SecuredSSL       SecuredMethod = "ssl"
	SecuredTLS       SecuredMethod = "tls"
)

type TransportValue string

var (
	TransportInsecure TransportValue = "insecure"
	TransportTrusted  TransportValue = "trusted"
	TransportTLS      TransportValue = "tls"
)

type AuthReq struct {
	RequestID string
	Mechanism string
	Service   string

	LocalIP   net.IP
	LocalPort uint16

	RemoteIP   net.IP
	RemotePort uint16

	Secured       bool
	SecuredMethod SecuredMethod

	Transport     string
	TLSCipher     string
	TLSCipherBits int
	TLSPFS        string
	TLSProtocol   string

	ValidClientCert bool
	NoPenalty       bool
	CertUsername    string
	ClientID        string // IMAP ID

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

	for i, p := range params[2:] {
		parts := strings.SplitN(p, "=", 2)
		switch parts[0] {
		case "resp":
			if len(parts) != 2 {
				return nil, fmt.Errorf("dovecotsasl: missing value for resp")
			}
			if i != len(params[2:])-1 {
				return nil, fmt.Errorf("dovecotsasl: resp should be the last parameter")
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
			if len(parts) == 2 {
				req.SecuredMethod = SecuredMethod(parts[1])
			}
		case "transport":
			if len(parts) != 2 {
				return nil, fmt.Errorf("dovecotsasl: missing transport argument")
			}
			req.Transport = parts[1]
		case "tls_cipher":
			if len(parts) != 2 {
				return nil, fmt.Errorf("dovecotsasl: missing tls_cipher argument")
			}
			req.TLSCipher = parts[1]
		case "tls_cipher_bits":
			if len(parts) != 2 {
				return nil, fmt.Errorf("dovecotsasl: missing tls_cipher_bits argument")
			}
			bits, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("dovecotsasl: malformed tls_cipher parameter: %v", err)
			}
			req.TLSCipherBits = bits
		case "tls_pfs":
			if len(parts) != 2 {
				return nil, fmt.Errorf("dovecotsasl: missing tls_pfs argument")
			}
			req.TLSPFS = parts[1]
		case "tls_protocol":
			if len(parts) != 2 {
				return nil, fmt.Errorf("dovecotsasl: missing tls_protocol argument")
			}
			req.TLSProtocol = parts[1]
		case "valid-client-cert":
			req.ValidClientCert = true
		case "no-penalty":
			req.NoPenalty = true
		case "cert_username":
			if len(parts) != 2 {
				return nil, fmt.Errorf("dovecotsasl: missing cert_username argument")
			}
			req.CertUsername = parts[1]
		case "client_id":
			if len(parts) != 2 {
				return nil, fmt.Errorf("dovecotsasl: missing client_id argument")
			}
			req.ClientID = parts[1]
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
