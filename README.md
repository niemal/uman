# uman
A hacky user manager, using a CSV format to store/load the database into/from a file.
The idea is to create an abstract yet adaptive, as minimal as possible, user manager.


## Examples
A simple straight-forward abstract usage.
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

An implemenetation with cookies and [gin](https://github.com/gin-gonic/gin).
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