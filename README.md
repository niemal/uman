# uman
A thread-safe user manager, using a simple format (`user:passhash\n`) to store/load the database into/from a file.
It can be used in any type of server, with HTTP being the only protocol to have a special feature (cookies, uses `net/http`).
The idea is to create an abstract yet adaptive, as minimal as possible user manager.


## API

### Initialising
One would need to call the constructor, which is the function below.
A string must be passed which states the database path to be created or used (both hanlded internally).
```go
func New(databasePath string) *UserManager
```

The UserManager struct:
```go
type UserManager struct {
	Users          map[string][]byte
	DatabasePath   string
	Sessions       map[string]*Session
	CheckDelay     int
	SessionsMutex  bool
	UsersMutex     bool
	Debugging      bool
}

```

`CheckDelay` states the cooldown of the thread responsible for handling session cleanup. Can be changed after initialization.

### Database structure
Currently it is kept as minimal as possible, using `user:passhash\n` text entries.
Option to use SQL type of engines/drivers is considered for the future.

### Database interaction
There are 2 functions which act as middlemen between you and the database.
More might be added later on (`Delete` is in mind).

First, one would need to register a user.
```go
func (um *UserManager) Register(user string, pass string) bool
```
In case the registration failed (user already exists, or user/pass is an empty string) it returns false.

Then, you are able to change a user's password with the function below.
Notice: The old password is required for security sake.
```go
func (um *UserManager) ChangePass(user string, oldpass string, newpass string) bool
```

**Note:** `uman` uses `bcrypt` for password hashing.

### Session handling
`uman` handles sessions for you, while you can also implement your special session handling or even
interconnect a different session architecture with this one.

There are 2 functions which you can use to retrieve a session.

```go
func (um *UserManager) GetSessionFromID(id string) *Session
```
The `GetSessionFromID` function attempts to find an existing session, given its identifier `id string`.
If no matching session is found, a new one is created and returned.

```go
func (um *UserManager) GetHTTPSession(w http.ResponseWriter, r *http.Request) *Session
```
The `GetHTTPSession` function is made to handle HTTP oriented type of sessions and internally also handles
cookie distribution and management. It produces a **SHA256 hash** by combining the user's agent and IP strings so the user
becomes trackable in the future. Furthermore, it also sets a cookie (if the session is new) of which the value is
a **unique** (it keeps trying to create a hash if collisions happen) pseudo-random **SHA256 hash** hex string.
The cookie exists for security and identifying reasons:
One given the same IP as a victim and by also knowing the victim's user agent they could fully impersonate the victim.


### Session struct
```go
type Session struct {
	User       string
	Timestamp  int64
	Lifespan   int64
	Cookie     string
	CookiePath string
}
```
If a user is not logged in then the `Session.User` is just an empty string, otherwise it's the user's name.
If `GetHTTPSession()` is not being used then the `Session.Cookie` will always be an empty string.

Functions related:
```go
func (sess *Session) SetHTTPCookie(w http.ResponseWriter)
```
Sets the appropriate cookie. You may set a `Session.CookiePath` (default is "/") before using `Session.SetHTTPCookie()`.

```go
func (sess *Session) SetLifespan(seconds int)
```
Sets the lifespan of a session. If using HTTP oriented sessions, you should also use `SetHTTPCookie()` after using this function.

```go
func (sess *Session) IsLogged() bool
```
Checks if the session holds a logged user.

```go
func (sess *Session) Logout()
```
Logs a session out (does not destroy the session).


## Examples
Feel free to build and run the tests with `cd tests; go build` and edit them locally to perceive the behaviour.

A simple straight-forward abstract usage:
```go
package main

import "github.com/niemal/uman"

func main() {
	um := uman.New("/tmp/my.db")
	um.Register("root", "mypass")

	// ... code ...

	session := um.GetSessionFromID("some unique identifying info related to the user")
	um.Login("root", "mypass", session)
	
	// ... code ...

	session.Logout()
}
```

An implemenetation with cookies and [gin](https://github.com/gin-gonic/gin):
```go
package main

import (
	"github.com/niemal/uman"
	"github.com/gin-gonic/gin"
	"net/http"
)

func main() {
	router := gin.Default()
	um := um.New("/tmp/data")
	um.Register("admin", "s3cr3t")

	router.GET("/user/:name", func (c *gin.Context) {
		session := um.GetHTTPSession(c.Writer, c.Request)
		user := c.Param("name")

		if user == "" || session.User != user {
			http.Redirect(c.Writer, c.Request, "/", 302)
			return
		}

		c.String(http.StatusOK, "Hello %s", user)
	})

	router.POST("/register", func (c *gin.Context) {
		session := um.GetHTTPSession(c.Writer, c.Request)

		if session.IsLogged() {
			http.Redirect(c.Writer, c.Request, "/user/" + session.User, 302)
			return
		}

		user, pass, repeat := c.PostForm("user"), c.PostForm("pass"), c.PostForm("repeat")

		result := false
		if pass == repeat  {
			result = um.Register(user, pass)
		}

		if result {
			um.Login(user, pass, session)
		}

		http.Redirect(c.Writer, c.Request, "/user/" + session.User, 302)
	})

	router.POST("/login", func (c *gin.Context) {
		session := um.GetHTTPSession(c.Writer, c.Request)

		um.Login(c.PostForm("user"), c.PostForm("pass"), session)

		if session.IsLogged() {
			http.Redirect(c.Writer, c.Request, "/user/" + session.User, 302)
		} else {
			http.Redirect(c.Writer, c.Request, "/", 302)
		}
		
	})

	router.Run(":8080")
}
```

## Documentation

API documentation is in progress, for now you may read the code or the examples above.

## License
[GNU Affero General Public License](http://www.gnu.org/licenses/agpl-3.0.html)