package v3api

import (
	"net/http"
	"strings"
	"github.com/dgrijalva/jwt-go"
	"fmt"
	"github.com/go-gorp/gorp"
	"github.com/decred/dcrstakepool/models"
	"github.com/zenazn/goji/web"
	"strconv"
	"time"
)

func ApplyTicketAuth(c *web.C, h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v3") {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, customAuthScheme) {
				var timestampMessage, timestampSignature string
				authParams := strings.Split(authHeader, ",")
				for _, param := range authParams {
					paramKeyValue := strings.Split(param, "=")
					if len(paramKeyValue) != 2 {
						continue
					}
					if key := strings.TrimSpace(paramKeyValue[0]); key == customAuthTimestampParam {
						timestampMessage = strings.TrimSpace(paramKeyValue[1])
					} else if key == customAuthSignatureParam {
						timestampSignature = strings.TrimSpace(paramKeyValue[1])
					}
				}

				JWTtoken, err := jwt.Parse(apitoken, func(token *jwt.Token) (interface{}, error) {
					// validate signing algorithm
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
					}
					return []byte(application.APISecret), nil
				})

				if err != nil {
					log.Warnf("invalid token %v: %v", apitoken, err)
				} else if claims, ok := JWTtoken.Claims.(jwt.MapClaims); ok && JWTtoken.Valid {
					dbMap := c.Env["DbMap"].(*gorp.DbMap)

					user, err := models.GetUserById(dbMap, int64(claims["loggedInAs"].(float64)))
					if err != nil {
						log.Errorf("unable to map apitoken %v to user id %v", apitoken, claims["loggedInAs"])
					} else {
						c.Env["APIUserID"] = user.Id
						log.Infof("mapped apitoken %v to user id %v", apitoken, user.Id)
					}
				}
			}
		}
		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}
