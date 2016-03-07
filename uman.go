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

type Session struct {
	User       string
	Timestamp  int64
	Lifespan   int64
	Cookie     string
	CookiePath string
}

type UserManager struct {
	Users         map[string][]byte
	DatabasePath  string
	Sessions      map[string]*Session
	CheckDelay    int
	Debugging     bool
}

const lifespan int64 = 3600

/**
 * Constructor of Session.
 *
 **/
func CreateSession() *Session {
	return &Session{
		User:       "",
		CookiePath: "/",
		Lifespan:   lifespan,
		Timestamp:  time.Now().Unix(),
	}
}

/**
 * Sets the HTTP cookie given the http.ResponseWriter.
 *
 **/
func (sess *Session) SetHTTPCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Path:     sess.CookiePath,
		Value:    sess.Cookie,
		HttpOnly: true,
		Expires:  time.Unix(sess.Timestamp + sess.Lifespan, 0),
		MaxAge:   int(sess.Lifespan),
	})
}

/**
 * Logs out the Session.
 *
 **/
func (sess *Session) Logout() {
	sess.User = ""
}

/**
 * Changes the lifespan of a Session.
 * Mainly exists to handle the typecasting between int and int64.
 *
 **/
func (sess *Session) SetLifespan(seconds int) {
	sess.Lifespan = int64(seconds)
}

/**
 * Checks if a Session is logged.
 *
 **/
func (sess *Session) IsLogged() bool {
	if sess.User != "" {
		return true
	}

	return false
}

/**
 * Constructor of UserManager.
 *
 **/
func New(databasePath string) *UserManager {
	um := &UserManager{
		DatabasePath: databasePath,
		Sessions:     make(map[string]*Session),
		Debugging:    true,
		CheckDelay:   60,
	}

	um.Reload()
	go um.CheckSessions()

	return um
}

/**
 * Handles checking for debug mode and if so prints text.
 *
 **/
func (um *UserManager) Debug(message string) {
	if um.Debugging {
		fmt.Println("[UserManager]: " + message)
	}
}

/**
 * Hashes any given input using bcrypt.
 *
 **/
func (um *UserManager) Hash(this []byte) []byte {
	// cost: minimum is 4, max is 31, default is 10
	// (https://godoc.org/golang.org/x/crypto/bcrypt)
	cost := 10

	hash, err := bcrypt.GenerateFromPassword(this, cost)
	um.Check(err)

	return hash
}

/**
 * Checks a hash against its possible plaintext. This exists because of
 * bcrypt's mechanism, we shouldn't just um.Hash() and check it ourselves.
 *
 **/
func (um *UserManager) CheckHash(hash []byte, original []byte) bool {
	if bcrypt.CompareHashAndPassword(hash, original) != nil {
		return false
	}

	return true
}

/**
 * Internal UserManager error handling. Specifically, if a path error occurs
 * that means we just need to create the database. Furthermore in debug mode
 * a stdout message pops before panic()'ing, due to a panic possibility occuring
 * out of the blue.
 *
 **/
func (um *UserManager) Check(err error) {
	if err != nil {
		if _, ok := err.(*os.PathError); ok {
			um.Debug("Path error occured, creating database now.")
			os.Create(um.DatabasePath)
		} else {
			um.Debug(err.Error() + "\nPanicking.")
			panic(err)
		}
	}
}

/**
 * Reloads the database into memory, filling the appropriate variables.
 *
 **/
func (um *UserManager) Reload() {
	um.Users = make(map[string][]byte) // reset

	data, err := ioutil.ReadFile(um.DatabasePath)
	um.Check(err)

	accounts := strings.Split(string(data), "\n")
	for _, acc := range accounts {
		creds := strings.Split(acc, ":")

		if len(creds) != 2 {
			// at times for unknown reasons the length of creds is 1
			// which causes an unchecked panic to pop. it shouldn't mind us.
			break
		}

		um.Users[creds[0]] = []byte(creds[1])
	}
}

/**
 * Registers a new User, writing both into the database file and the memory.
 *
 **/
func (um *UserManager) Register(user string, pass string) bool {
	if _, exists := um.Users[user]; exists || user == "" || pass == "" {
		return false
	}

	um.Users[user] = um.Hash([]byte(pass))
	pass = string(um.Users[user])

	f, err := os.OpenFile(um.DatabasePath, os.O_APPEND|os.O_WRONLY, 0666)
	defer f.Close()
	um.Check(err)

	_, err = f.WriteString(user + ":" + pass + "\n")
	um.Check(err)

	um.Debug("Registered user[" + user + "] with password[" + pass + "].")
	return true
}

/**
 * Changes the password of a User, given his old password matches the oldpass input variable.
 * Writes both into the database file and the memory.
 *
 * Returns false if the old password given doesn't match the actual old password, or User
 * doesn't exist.
 *
 **/
func (um *UserManager) ChangePass(user string, oldpass string, newpass string) bool {
	if newpass != "" && um.CheckHash(um.Users[user], []byte(oldpass)) {
		oldpass := string(um.Users[user])
		um.Users[user] = um.Hash([]byte(newpass))
		newpass = string(um.Users[user])

		data, err := ioutil.ReadFile(um.DatabasePath)
		um.Check(err)

		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if strings.Contains(line, user) && strings.Contains(line, oldpass) {
				lines[i] = user + ":" + newpass
				break
			}
		}

		output := strings.Join(lines, "\n")
		err = ioutil.WriteFile(um.DatabasePath, []byte(output), 0666)
		um.Check(err)

		um.Debug("Changed the password of user[" + user + "],\n\t" +
			"from[" + oldpass + "] to[" + newpass + "].")
		return true
	}

	um.Debug("Failed to change the password of User[" + user + "].")
	return false
}

/**
 * Checks for expired Sessions.
 *
 **/
func (um *UserManager) CheckSessions() {
	for {
		for hash, sess := range um.Sessions {
			if sess.Timestamp+sess.Lifespan < time.Now().Unix() {
				um.Debug("Session[" + hash + "] has expired.")
				delete(um.Sessions, hash)
			}
		}

		time.Sleep(time.Duration(um.CheckDelay) * time.Second)
	}
}

/**
 * Uses SHA256 to hash a Session token (the sum of identifiers).
 *
 **/
func (um *UserManager) HashHTTPSessionToken(ua string, ip string) string {
	hash := sha256.New()
	hash.Write([]byte(ua + ip))
	
	return hex.EncodeToString(hash.Sum(nil))
}

/**
 * Generates a unique cookie hash (it keeps trying if not).
 *
 **/
func (um *UserManager) GenerateCookieHash() string {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	um.Check(err)

    hash := sha256.New()
    hash.Write(randBytes)
    
    result := hex.EncodeToString(hash.Sum(nil))
    for _, sess := range um.Sessions {
    	if sess.Cookie == result {
    		return um.GenerateCookieHash()
    	}
    }

    return result
}

/**
 * This function is made for HTTP oriented sessions.
 * It attempts to find an existing Session. If it exists, it validates
 * the given cookie (from the Request). If vaildation fails it's like the
 * Session never existed in the first place, having a fresh one taking its
 * place. Returns nil if http.Request or http.ResponseWriter are nil.
 *
 **/
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

	hash := um.HashHTTPSessionToken(r.UserAgent(), ip)

	if sess, exists := um.Sessions[hash]; exists {
		userCookie, err := r.Cookie("session")

		if err == nil && userCookie.Value == sess.Cookie {
			return sess
		}
	}

	um.Sessions[hash] = CreateSession()
	sess := um.Sessions[hash]
	
	sess.Cookie = um.GenerateCookieHash()
	sess.SetHTTPCookie(w)
	
	return sess
}

/**
 * This function is made for the non cookie (abstract) mode. If a Session is not
 * found a new one takes its place.
 *
 **/
func (um *UserManager) GetSessionFromID(id string) *Session {
	if sess, exists := um.Sessions[id]; exists {
		return sess
	}

	um.Sessions[id] = CreateSession()
	return um.Sessions[id]
}

/**
 * Pretty simple.
 *
 **/
func (um *UserManager) Login(user string, pass string, sess *Session) bool {
	if user != "" && pass != "" && um.CheckHash(um.Users[user], []byte(pass)) {
		sess.User = user

		um.Debug("User[" + user + "] has logged in.")
		return true
	}

	um.Debug("User[" + user + "] failed to log in.")
	return false
}