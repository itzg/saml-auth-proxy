package server

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// List of headers to exclude
var websocketExcludeHeaders = map[string]bool{
	"sec-websocket-key":        true,
	"sec-websocket-version":    true,
	"sec-websocket-accept":     true,
	"sec-websocket-protocol":   true,
	"sec-websocket-extensions": true,
	"upgrade":                  true,
	"connection":               true,
}

func (p *Proxy) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Create backend URL for WebSocket connection
	backendURL := *p.backendUrl
	if backendURL.Scheme == "http" {
		backendURL.Scheme = "ws"
	} else if backendURL.Scheme == "https" {
		backendURL.Scheme = "wss"
	}
	backendURL.Path = r.URL.Path
	backendURL.RawQuery = r.URL.RawQuery

	// Try a quick probe first with a short timeout
	probeDialer := websocket.Dialer{
		HandshakeTimeout: 2 * time.Second,
	}

	// Create clean header set for the probe
	probeHeader := http.Header{}
	for k, v := range r.Header {
		headerName := strings.ToLower(k)
		if !websocketExcludeHeaders[headerName] {
			probeHeader[k] = v
		}
	}

	// Try to connect to check if WebSocket is supported
	probeConn, probeResp, err := probeDialer.Dial(backendURL.String(), probeHeader)
	if err != nil {
		if probeResp != nil && probeResp.Body != nil {
			probeResp.Body.Close()
		}
		// Log the failure and return - this will cause the main handler to fall back to HTTP
		p.logger.Debug("WebSocket not supported by backend, falling back to HTTP",
			zap.String("path", r.URL.Path),
			zap.Error(err))
		return
	}
	probeConn.Close()

	// If we get here, WebSocket is supported - proceed with the actual connection
	clientConn, err := p.upgrader.Upgrade(w, r, nil)
	if err != nil {
		p.logger.Error("Failed to upgrade client connection", zap.Error(err))
		return
	}
	defer clientConn.Close()

	// Connect to the backend WebSocket server
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	// Create clean header set for the backend connection
	requestHeader := http.Header{}
	for k, v := range r.Header {
		headerName := strings.ToLower(k)
		if !websocketExcludeHeaders[headerName] {
			requestHeader[k] = v
		}
	}

	// Add forwarded headers
	requestHeader.Set(HeaderForwardedHost, r.Host)
	if remoteHost, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		requestHeader.Set(HeaderForwardedFor, remoteHost)
	}
	requestHeader.Set(HeaderForwardedProto, "ws")

	backendConn, resp, err := dialer.Dial(backendURL.String(), requestHeader)
	if err != nil {
		p.logger.Error("Failed to connect to backend",
			zap.Error(err),
			zap.String("backend_url", backendURL.String()))
		return
	}
	defer backendConn.Close()
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	// Bidirectional copy of messages
	errorChan := make(chan error, 2)

	// Copy messages from client to backend
	go func() {
		for {
			messageType, message, err := clientConn.ReadMessage()
			if err != nil {
				errorChan <- err
				return
			}
			err = backendConn.WriteMessage(messageType, message)
			if err != nil {
				errorChan <- err
				return
			}
		}
	}()

	// Copy messages from backend to client
	go func() {
		for {
			messageType, message, err := backendConn.ReadMessage()
			if err != nil {
				errorChan <- err
				return
			}
			err = clientConn.WriteMessage(messageType, message)
			if err != nil {
				errorChan <- err
				return
			}
		}
	}()

	// Wait for error or connection close
	err = <-errorChan
	if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
		p.logger.Error("WebSocket error", zap.Error(err))
	}
}
