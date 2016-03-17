// Package uman is a minimal user and session manager in Golang.
// Copyright (C) 2016 niemal
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
package uman

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

// Session is a structure representing what its name implies.
//
type Session struct {
	User       string
	Timestamp  int64
	Lifespan   int64
	Cookie     string
	CookiePath string
}

const lifespan int64 = 3600

// Constructor of Session.
func createSession() *Session {
	return &Session{
		User:       "",
		CookiePath: "/",
		Lifespan:   lifespan,
		Timestamp:  time.Now().Unix(),
	}
}

// SetHTTPCookie sets the HTTP cookie given the http.ResponseWriter.
//
func (sess *Session) SetHTTPCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Path:     sess.CookiePath,
		Value:    sess.Cookie,
		HttpOnly: true,
		Expires:  time.Unix(sess.Timestamp+sess.Lifespan, 0),
		MaxAge:   int(sess.Lifespan),
	})
}

// Logout logs the session out!
//
func (sess *Session) Logout() {
	sess.User = ""
}

// SetLifespan changes the lifespan of a Session.
// Mainly exists to handle the typecasting between int and int64.
//
func (sess *Session) SetLifespan(seconds int) {
	sess.Lifespan = int64(seconds)
}

// IsLogged checks if the Session holds a user.
//
func (sess *Session) IsLogged() bool {
	if sess.User != "" {
		return true
	}

	return false
}

// UserManager is the backbone, holding all the goods.
//
type UserManager struct {
	CheckDelay    int
	Debug         bool
	users         map[string][]byte
	sessions      map[string]*Session
	databasePath  string
	sessionsMutex bool
	usersMutex    bool
}

// New is the constructor of UserManager.
//
func New(dbPath string) *UserManager {
	um := &UserManager{
		Debug:         true,
		CheckDelay:    60,
		databasePath:  dbPath,
		sessions:      make(map[string]*Session),
		sessionsMutex: false,
		usersMutex:    false,
	}

	um.reload()
	go um.checkSessions()

	return um
}

// Handles checking for debug mode and if so prints text.
func (um *UserManager) debug(message string) {
	if um.Debug {
		fmt.Println("[UserManager]: " + message)
	}
}

// Locks the running thread to prevent race conditions.
// A boolean is provided as the responsible mutex. Usually it's
// um.sessionsMutex or um.usersMutex.
func (um *UserManager) lock(mutex *bool) {
	um.debug("Thread is locked.")

	for *mutex {
		time.Sleep(time.Duration(300) * time.Millisecond)
	}

	um.debug("Thread is unlocked.")
}

// Reloads the database into memory, filling the appropriate variables.
func (um *UserManager) reload() {
	um.lock(&um.usersMutex)
	um.usersMutex = true

	um.users = make(map[string][]byte) // reset

	data, err := ioutil.ReadFile(um.databasePath)
	um.check(err)

	accounts := strings.Split(string(data), "\n")
	for _, acc := range accounts {
		creds := strings.Split(acc, ":")

		if len(creds) != 2 {
			break
		}

		um.users[creds[0]] = []byte(creds[1])
	}

	um.usersMutex = false
}

// Checks for expired Sessions.
func (um *UserManager) checkSessions() {
	for {
		for hash, sess := range um.sessions {
			if sess.Timestamp+sess.Lifespan < time.Now().Unix() {
				um.lock(&um.sessionsMutex)
				um.sessionsMutex = true

				um.debug("Session[" + hash + "] has expired.")
				delete(um.sessions, hash)

				um.sessionsMutex = false
			}
		}

		time.Sleep(time.Duration(um.CheckDelay) * time.Second)
	}
}

// Hashes any given input using bcrypt.
func (um *UserManager) hash(this []byte) []byte {
	// cost: minimum is 4, max is 31, default is 10
	// (https://godoc.org/golang.org/x/crypto/bcrypt)
	cost := 10

	hash, err := bcrypt.GenerateFromPassword(this, cost)
	um.check(err)

	return hash
}

// CheckHash checks a hash against its possible plaintext. This exists because of
// bcrypt's mechanism, we shouldn't just um.hash() and check it ourselves.
func (um *UserManager) checkHash(hash []byte, original []byte) bool {
	if bcrypt.CompareHashAndPassword(hash, original) != nil {
		return false
	}

	return true
}

// Check is for internal UserManager error handling. Specifically, if a path error occurs
// that means we just need to create the database. Furthermore in debug mode
// a stdout message pops before panic()'ing, due to a panic possibility occurring
// out of the blue.
func (um *UserManager) check(err error) {
	if err != nil {
		if _, ok := err.(*os.PathError); ok {
			um.debug("Path error occured, creating database now.")
			os.Create(um.databasePath)
		} else {
			um.debug(err.Error() + "\nPanicking.")
			panic(err)
		}
	}
}

// Uses SHA256 to hash a Session token (the sum of identifiers).
func (um *UserManager) hashHTTPSessionToken(ua string, ip string) string {
	hash := sha256.New()
	hash.Write([]byte(ua + ip))

	return hex.EncodeToString(hash.Sum(nil))
}

// Generates a unique cookie hash (it keeps trying if not).
func (um *UserManager) generateCookieHash() string {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	um.check(err)

	hash := sha256.New()
	hash.Write(randBytes)

	result := hex.EncodeToString(hash.Sum(nil))
	for _, sess := range um.sessions {
		if sess.Cookie == result {
			return um.generateCookieHash()
		}
	}

	return result
}

// GetHTTPSession is made for HTTP oriented sessions.
// It attempts to find an existing Session. If it exists, it validates
// the given cookie (from the Request). If vaildation fails it's like the
// Session never existed in the first place, having a fresh one taking its
// place. Returns nil if either http.Request or http.ResponseWriter are nil.
//
func (um *UserManager) GetHTTPSession(w http.ResponseWriter, r *http.Request) *Session {
	if r == nil || w == nil {
		return nil
	}

	sep := ":"
	if strings.Contains(r.RemoteAddr, "%") {
		// it's ipv6
		sep = "%"
	}

	chopped := strings.SplitN(r.RemoteAddr, sep, 2)
	ip := ""

	if len(chopped) > 1 {
		ip = chopped[0]
	}

	hash := um.hashHTTPSessionToken(r.UserAgent(), ip)

	if sess, exists := um.sessions[hash]; exists {
		userCookie, err := r.Cookie("session")

		if err == nil && userCookie.Value == sess.Cookie {
			return sess
		}
	}

	um.lock(&um.sessionsMutex)
	um.sessionsMutex = true
	um.sessions[hash] = createSession()
	um.sessionsMutex = false

	sess := um.sessions[hash]

	sess.Cookie = um.generateCookieHash()
	sess.SetHTTPCookie(w)

	return sess
}

// GetSessionFromID is made for abstraction. One could produce IDs given
// unique user oriented identifying elements. If a Session is not found
// a new one takes its place and gets returned.
//
func (um *UserManager) GetSessionFromID(id string) *Session {
	if sess, exists := um.sessions[id]; exists {
		return sess
	}

	um.lock(&um.sessionsMutex)
	um.sessionsMutex = true
	um.sessions[id] = createSession()
	um.sessionsMutex = false

	return um.sessions[id]
}

// Register registers a new user, writing both into the database file and the memory.
// Returns false if the user exists already.
//
func (um *UserManager) Register(user string, pass string) bool {
	if _, exists := um.users[user]; exists || user == "" || pass == "" {
		return false
	}

	um.lock(&um.usersMutex)
	um.usersMutex = true
	um.users[user] = um.hash([]byte(pass))
	um.usersMutex = false

	pass = string(um.users[user])

	f, err := os.OpenFile(um.databasePath, os.O_APPEND|os.O_WRONLY, 0666)
	defer f.Close()
	um.check(err)

	_, err = f.WriteString(user + ":" + pass + "\n")
	um.check(err)

	um.debug("Registered user[" + user + "] with password[" + pass + "].")
	return true
}

// ChangePass changes the password of a user, given his old password matches the oldpass
// string variable. Writes both into the database file and the memory.
//
// Returns false if the old password given doesn't match the actual old password, or User
// doesn't exist.
//
func (um *UserManager) ChangePass(user string, oldpass string, newpass string) bool {
	if newpass != "" && um.checkHash(um.users[user], []byte(oldpass)) {
		oldpass := string(um.users[user])

		um.lock(&um.usersMutex)
		um.usersMutex = true
		um.users[user] = um.hash([]byte(newpass))
		um.usersMutex = false

		newpass = string(um.users[user])

		data, err := ioutil.ReadFile(um.databasePath)
		um.check(err)

		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if strings.Contains(line, user) && strings.Contains(line, oldpass) {
				lines[i] = user + ":" + newpass
				break
			}
		}

		output := strings.Join(lines, "\n")
		err = ioutil.WriteFile(um.databasePath, []byte(output), 0666)
		um.check(err)

		um.debug("Changed the password of user[" + user + "],\n\t" +
			"from[" + oldpass + "] to[" + newpass + "].")
		return true
	}

	um.debug("Failed to change the password of User[" + user + "].")
	return false
}

// Login logs a user in given his credentials.
//
func (um *UserManager) Login(user string, pass string, sess *Session) bool {
	if user != "" && pass != "" && um.checkHash(um.users[user], []byte(pass)) {
		sess.User = user

		um.debug("User[" + user + "] has logged in.")
		return true
	}

	um.debug("User[" + user + "] failed to log in.")
	return false
}
