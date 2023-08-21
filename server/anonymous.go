package server

import (
	"errors"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"go.uber.org/zap"
	"net/http"
)

type AnonymousSession struct {
}

func IsAnonymousSession(session samlsp.Session) bool {
	_, isAnonymous := session.(AnonymousSession)
	return isAnonymous
}

type InitAnonymousSessionProvider struct {
	delegateSessionProvider samlsp.SessionProvider
	initiateSessionPath     string
	logger                  *zap.Logger
}

// NewInitAnonymousSessionProvider will initially provide AnonymousSession instances when requested; however,
// once the given initiateSessionPath is intercepted, then remaining session access is delegated to the
// given delegateSessionProvider.
func NewInitAnonymousSessionProvider(logger *zap.Logger, initiateSessionPath string, delegateSessionProvider samlsp.SessionProvider) *InitAnonymousSessionProvider {
	return &InitAnonymousSessionProvider{
		delegateSessionProvider: delegateSessionProvider,
		initiateSessionPath:     initiateSessionPath,
		logger:                  logger.With(zap.String("scope", "InitAnonymousSessionProvider")),
	}
}

func (p *InitAnonymousSessionProvider) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	return p.delegateSessionProvider.CreateSession(w, r, assertion)
}

func (p *InitAnonymousSessionProvider) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	return p.delegateSessionProvider.DeleteSession(w, r)
}

func (p *InitAnonymousSessionProvider) GetSession(r *http.Request) (samlsp.Session, error) {
	session, err := p.delegateSessionProvider.GetSession(r)
	if err != nil {
		if errors.Is(err, samlsp.ErrNoSession) {
			if r.URL.Path == p.initiateSessionPath {
				p.logger.Debug("Intercepted initiate session path", zap.String("path", r.URL.Path))
				return nil, samlsp.ErrNoSession
			}
			p.logger.Debug("Auth has not been initiated, returning anonymous session", zap.String("path", r.URL.Path))
			return AnonymousSession{}, nil
		} else {
			return nil, err
		}
	} else {
		return session, nil
	}
}
