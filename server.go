package dovecotsasl

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"

	"github.com/emersion/go-sasl"
)

type Server struct {
	l        []net.Listener
	mechInfo map[string]Mechanism
	mechImpl map[string]func(*AuthReq) sasl.Server
	Log      *log.Logger
}

func NewServer() *Server {
	return &Server{
		mechInfo: map[string]Mechanism{},
		mechImpl: map[string]func(*AuthReq) sasl.Server{},
		Log:      log.New(ioutil.Discard, "", 0),
	}
}

func (s *Server) AddMechanism(name string, info Mechanism, handler func(*AuthReq) sasl.Server) {
	s.mechInfo[name] = info
	s.mechImpl[name] = handler
}

func (s *Server) Serve(l net.Listener) error {
	s.l = append(s.l, l)
	for {
		netConn, err := l.Accept()
		if err != nil {
			return err
		}

		go s.handleConn(netConn)
	}
}

func (s *Server) handleConn(netConn net.Conn) {
	conn := conn{
		C: netConn,
		W: bufio.NewWriter(netConn),
		R: bufio.NewScanner(netConn),
	}
	defer conn.Close()

	_, err := conn.handshakeServer(s.mechInfo)
	if err != nil {
		s.Log.Println("I/O error:", err)
		return
	}

	for {
		err := s.handleAuth(&conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.Log.Println("Protocol error:", err)
			}
			return
		}
	}
}

func (s *Server) handleAuth(c *conn) error {
	params, err := c.ReadlnExpect("AUTH", 3)
	if err != nil {
		return err
	}

	req, err := parseAuthReq(params)
	if err != nil {
		return err
	}

	handler := s.mechImpl[req.Mechanism]
	if handler == nil {
		err = c.Writeln("FAIL", AuthFail{
			RequestID: req.RequestID,
			Reason:    "unsupported mechanism",
		}.format()...)
		if err != nil {
			return err
		}
	}

	serv := handler(req)

	for {
		challenge, done, err := serv.Next(req.IR)
		if err != nil {
			err = c.Writeln("FAIL", AuthFail{
				RequestID: req.RequestID,
				Reason:    "authentication failed",
			}.format()...)
			if err != nil {
				return err
			}
		}
		if done {
			break
		}
		if err = c.Writeln("CONT", req.RequestID, base64.StdEncoding.EncodeToString(challenge)); err != nil {
			return err
		}
	}

	return c.Writeln("OK", req.RequestID)
}

func (s *Server) Close() error {
	for _, l := range s.l {
		l.Close()
	}
	return nil
}
