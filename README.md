# uman
A hacky user manager, using a CSV format to store/load the database into/from a file.
The idea is to create an abstract yet adaptive, as minimal as possible, full-backend user manager.
Handling user management under the actual server software might come in handy and *fast*.


## API

### Initializing
One would need to call the constructor, which is the function below.
A string must be passed which states the database path to be created or used (both hanlded internally).
```go
func New(databasePath string) *UserManager
```

The UserManager struct is as follows:
```go
type UserManager struct {
	Users        map[string][]byte
	DatabasePath string
	Sessions     map[string]*Session
	Request      *http.Request
	Writer       http.ResponseWriter
	Debugging    bool
}
```

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

_Note:_ `uman` uses `bcrypt` for password hashing.

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
func (um *UserManager) GetHTTPSession() *Session
```
The `GetHTTPSession` function is made to handle HTTP oriented type of sessions and internally also handles
cookie distribution and management. It produces a _SHA256 hash_ by combining the user's agent and IP strings so the user
becomes trackable in the future. Furthermore, it also sets a cookie (if the session is new) of which the value is
a _unique_ (it keeps trying to create a hash if collisions happen) pseudo-random _SHA256 hash_ hex string.
The cookie exists for security and identifying reasons:
One given the same IP as a victim and by also knowing the victim's user agent they could fully impersonate the victim.

To use this function, you must handle assigning the proper `Request *http.Request` and `Writer http.ResponseWriter`
variables to your `UserManager` type of object.

A quick example of a function named `Adapt` which handles returning the appropriate HTTP session:
```go
um := uman.New("/tmp/data")

func Adapt(w http.ResponseWriter, r *http.Request) *Session {
	um.Writer = w
	um.Request = r
	return um.GetHTTPSession()
}
```

### Session struct
```go
type Session struct {
	User      string
	Timestamp int64
	Lifespan  int64
	Cookie    string
}
```
If a user is not logged in then the `Session.User` is just an empty string, otherwise it's the user's name.
If `GetHTTPSession()` is not being used then the `Session.Cookie` will always be an empty string.

Functions related:

```go
func (sess *Session) SetLifespan(seconds int)
```
Sets the lifespan of a session.

```go
func (sess *Session) IsLogged() bool
```
Checks if the session holds a logged user.

```go
func (um *UserManager) Logout(sess *Session)
```
Logs a session out (does not destroy the session).


## Examples
Feel free to build the tests with `cd tests; go build` and edit them locally to perceive the behaviour.

A simple straight-forward abstract usage:
```go
package main

import "github.com/niemal/uman"

func main() {
	um := uman.New("/tmp/my.db")
	um.Register("root", "mypass")

	// ... code ...

	session := um.GetSessionFromID("some unique identifying info related to the user")
	// session := um.GetHTTPSession() // == nil, there is no http.Request object.

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

type Site struct {
	Router *gin.Engine
	Uman   *uman.UserManager
}

func New() *Site {
	return &Site{
		Router: gin.Default(),
		Uman:   uman.New("/tmp/my.db"),
	}
}

func (s *Site) Adapt(c *gin.Context) *uman.Session {
	s.Uman.Writer = c.Writer
	s.Uman.Request = c.Request
	return s.Uman.GetHTTPSession() 
}

func (s *Site) Redirect(path string) {
	http.Redirect(s.Uman.Writer, s.Uman.Request, path, 302)
}

func main() {
	site := New()
	site.Uman.Register("admin", "s3cr3t")

	site.Router.GET("/user/:name", func (c *gin.Context) {
		user := c.Param("name")
		session := site.Adapt(c)

		if session.User != user {
			site.Redirect("/")
			return
		}

		c.String(http.StatusOK, "Hello %s", user)
	})

	site.Router.POST("/register", func (c *gin.Context) {
		session := site.Adapt(c)

		if session.IsLogged() {
			site.Redirect("/" + session.User)
			return
		}

		user, pass, repeat := c.PostForm("user"), c.PostForm("pass"), c.PostForm("repeat")

		result := false
		if pass == repeat  {
			result = site.Uman.Register(user, pass)
		}

		if result {
			site.Uman.Login(user, pass, session)
			site.Redirect("/user/" + user)
		}
	})

	site.Router.POST("/login", func (c *gin.Context) {
		session := site.Adapt(c)
		site.Uman.Login(c.PostForm("user"), c.PostForm("pass"), session)
		
		if session.IsLogged() {
			site.Redirect("/user/" + session.User)
		} else {
			site.Redirect("/")
		}
		
	})

	site.Router.Run(":8080")
}
```

## Documentation

API documentation is in progress, for now you may read the code or the examples above.

## License
[GNU Affero General Public License](http://www.gnu.org/licenses/agpl-3.0.html)