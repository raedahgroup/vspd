package system

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/decred/dcrstakepool/models"
	"github.com/go-gorp/gorp"
	"github.com/gorilla/sessions"
	"github.com/zenazn/goji/web"
)

// Makes sure templates are stored in the context
func (application *Application) ApplyTemplates(c *web.C, h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		c.Env["Template"] = application.Template
		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

// Makes sure controllers can have access to session
func (application *Application) ApplySessions(c *web.C, h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		session, err := application.Store.New(r, "session")
		if err != nil {
			log.Warnf("session load err: %v ", err)
		}
		c.Env["Session"] = session
		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func (application *Application) ApplyDbMap(c *web.C, h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		c.Env["DbMap"] = application.DbMap
		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func (application *Application) ApplyAPI(c *web.C, h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api") {
			var user *models.User
			var err error
			dbMap := c.Env["DbMap"].(*gorp.DbMap)

			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				userId, authFailureReason := application.validateToken(authHeader)
				if authFailureReason != "" {
					err = fmt.Errorf(authFailureReason)
				} else {
					user, err = models.GetUserById(dbMap, userId)
				}
			} else if strings.HasPrefix(authHeader, "TicketAuth ") {
				userMsa, authFailureReason := application.validateTicketOwnership(authHeader)
				if authFailureReason != "" {
					err = fmt.Errorf(authFailureReason)
				} else {
					user, err = models.GetUserByMSA(dbMap, userMsa)
				}
			}

			if err != nil {
				log.Warnf("api authorization failure: %v", err)
				c.Env["AuthErrorMessage"] = err.Error()
			} else if user != nil {
				c.Env["APIUserID"] = user.Id
				log.Infof("mapped api auth header %v to user %v", authHeader, user.Id)
			}
		}

		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func (application *Application) ApplyCaptcha(c *web.C, h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		session := c.Env["Session"].(*sessions.Session)
		if done, ok := session.Values["CaptchaDone"].(bool); ok {
			c.Env["CaptchaDone"] = done
		} else {
			c.Env["CaptchaDone"] = false
		}
		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func (application *Application) ApplyAuth(c *web.C, h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		session := c.Env["Session"].(*sessions.Session)
		if userId := session.Values["UserId"]; userId != nil {
			dbMap := c.Env["DbMap"].(*gorp.DbMap)

			user, err := dbMap.Get(models.User{}, userId)
			if err != nil {
				log.Warnf("Auth error: %v", err)
				c.Env["User"] = nil
			} else {
				c.Env["User"] = user
			}
		}
		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}
