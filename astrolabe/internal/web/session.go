// Manage authenticated browser sessions and their expiry and request protections.

package web

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

// sessions holds fixed eight-hour process-local logins with monotonic timestamps and no sliding renewal.
type sessions struct {
	mutex   sync.Mutex           // Protect the session table only; generate randomness outside the lock.
	values  map[string]time.Time // Delete expired tokens on access without a background sweeper.
	maximum int                  // At capacity, only an existing session may be replaced.
}

// create atomically replaces this browser's previous token after KDF success, without revoking it before capacity and uniqueness checks pass.
// Generate randomness outside the lock so lookups never wait for the random source.
// Return a token and expiry, or false on failure; previous may be empty.
func (sessions *sessions) create(now time.Time, previous string) (string, time.Time, bool) {
	// Try at most four collision-free tokens; a random-source failure returns immediately.
	for attempt := 0; attempt < 4; attempt++ {
		var bytes [32]byte
		if _, err := rand.Read(bytes[:]); err != nil {
			return "", time.Time{}, false
		}
		token := base64.RawURLEncoding.EncodeToString(bytes[:])
		sessions.mutex.Lock()

		for key, expire := range sessions.values {
			if !now.Before(expire) {
				delete(sessions.values, key)
			}
		}
		_, replacing := sessions.values[previous]
		if len(sessions.values) >= sessions.maximum && !replacing {

			sessions.mutex.Unlock()
			return "", time.Time{}, false
		}
		if _, exists := sessions.values[token]; !exists {

			expire := now.Add(8 * time.Hour)
			sessions.values[token] = expire
			delete(sessions.values, previous)
			sessions.mutex.Unlock()
			return token, expire, true
		}
		sessions.mutex.Unlock()
	}
	return "", time.Time{}, false
}

// get validates the actual deadline on every admission without scanning the whole table.
func (sessions *sessions) get(token string, now time.Time) (time.Time, bool) {
	sessions.mutex.Lock()
	defer sessions.mutex.Unlock()
	expire, exists := sessions.values[token]
	if !exists || !now.Before(expire) {

		delete(sessions.values, token)
		return time.Time{}, false
	}
	return expire, true
}

// remove revokes server state before the response clears its cookie; missing tokens and repeated logout are harmless.
func (sessions *sessions) remove(token string) {
	sessions.mutex.Lock()
	delete(sessions.values, token)
	sessions.mutex.Unlock()
}

// token accepts one cookie only, without alternate URL, Authorization or localStorage credentials.
func token(request *http.Request) string {
	cookies := request.CookiesNamed("astra-session")
	if len(cookies) != 1 || len(cookies[0].Value) != 43 {
		// Require exactly one session cookie with the unpadded base64 length for 32 bytes.
		return ""
	}
	return cookies[0].Value
}

// cookie shares all scope attributes between creation and deletion, leaves Domain empty and never extends expiry on access.
// An empty value deletes the token; expire determines MaxAge.
func (server *Server) cookie(response http.ResponseWriter, value string, expire time.Time) {
	age := int(time.Until(expire) / time.Second)
	if value == "" || age <= 0 {

		value, age, expire = "", -1, time.Unix(1, 0)
	}
	mode := http.SameSiteLaxMode
	if server.crosssite {
		mode = http.SameSiteNoneMode
	}
	http.SetCookie(response, &http.Cookie{Name: "astra-session", Value: value, Path: "/api", Expires: expire, MaxAge: age, HttpOnly: true, Secure: server.secure, SameSite: mode})
}
