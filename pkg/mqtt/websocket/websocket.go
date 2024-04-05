// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package websocket

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/absmach/mproxy/pkg/session"
	mptls "github.com/absmach/mproxy/pkg/tls"
	"github.com/gorilla/websocket"
)

// Proxy represents WS Proxy.
type Proxy struct {
	target      string
	path        string
	scheme      string
	handler     session.Handler
	interceptor session.Interceptor
	logger      *slog.Logger
}

// New - creates new WS proxy.
func New(target, path, scheme string, handler session.Handler, interceptor session.Interceptor, logger *slog.Logger) *Proxy {
	return &Proxy{
		target:      target,
		path:        path,
		scheme:      scheme,
		handler:     handler,
		interceptor: interceptor,
		logger:      logger,
	}
}

var upgrader = websocket.Upgrader{
	// Timeout for WS upgrade request handshake
	HandshakeTimeout: 10 * time.Second,
	// Paho JS client expecting header Sec-WebSocket-Protocol:mqtt in Upgrade response during handshake.
	Subprotocols: []string{"mqttv3.1", "mqtt"},
	// Allow CORS
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Handler - proxies WS traffic.
func (p Proxy) Handler() http.Handler {
	return p.handle()
}

func (p Proxy) handle() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cconn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			p.logger.Error("Error upgrading connection", slog.Any("error", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		p.logger.Info("Upgraded connection, starting go routine to pass traffic")
		ctx := context.Background()
		if ctx.Err() != nil {
			p.logger.Warn("Context error just after upgrading connection", slog.Any("error", ctx.Err()))
			return
		}
		go p.pass(ctx, cconn)
	})
}

func (p Proxy) pass(ctx context.Context, in *websocket.Conn) {
	defer in.Close()
	p.logger.Info("Test log")

	if ctx.Err() != nil {
		p.logger.Warn("Context error just at the start of pass", slog.Any("error", ctx.Err()))
		return
	}

	websocketURL := url.URL{
		Scheme: p.scheme,
		Host:   p.target,
		Path:   p.path,
	}

	dialer := &websocket.Dialer{
		Subprotocols: []string{"mqtt"},
	}
	srv, _, err := dialer.Dial(websocketURL.String(), nil)
	if err != nil {
		p.logger.Error("Unable to connect to broker", slog.Any("error", err))
		return
	}

	if ctx.Err() != nil {
		p.logger.Warn("Context error after connecting to broker", slog.Any("error", ctx.Err()))
		return
	}

	errc := make(chan error, 1)
	inboundConn := newConn(in)
	outboundConn := newConn(srv)

	defer inboundConn.Close()
	defer outboundConn.Close()

	clientCert, err := mptls.ClientCert(in.UnderlyingConn())
	if err != nil {
		p.logger.Error("Failed to get client certificate", slog.Any("error", err))
		return
	}

	if err = ctx.Err(); err != nil {
		p.logger.Warn("Context error before starting proxy", slog.Any("error", err))
		return
	}

	err = session.Stream(ctx, inboundConn, outboundConn, p.handler, p.interceptor, clientCert, p.logger)
	errc <- err
	p.logger.Warn("Broken connection for client", slog.Any("error", err))
}

// Listen of the server.
func (p Proxy) Listen(wsPort string) error {
	port := fmt.Sprintf(":%s", wsPort)
	return http.ListenAndServe(port, nil)
}

// ListenTLS - version of Listen with TLS encryption.
func (p Proxy) ListenTLS(tlsCfg *tls.Config, crt, key, wssPort string) error {
	port := fmt.Sprintf(":%s", wssPort)
	server := &http.Server{
		Addr:      port,
		TLSConfig: tlsCfg,
	}
	return server.ListenAndServeTLS(crt, key)
}
