# uman
A hacky user manager, using a CSV format to store/load the database into/from a file.
The idea is to create an abstract, as minimal as possible, user manager.


## Examples
A simple straight-forward usage.
```go
package main

import "github.com/niemal/uman"

func main() {
	um := uman.New("/tmp/my.db")
	um.Register("root", "mypass")

	// ... code ...

	session := um.GetSession()
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
	site := &Site{
		Router: gin.Default(),
		Uman:   uman.New("my.db"),
	}

	site.Cookies = true
	return site
}

func (s *Site) Adapt(c *gin.Context) *uman.Session {
	s.Uman.Writer = c.Writer
	s.Uman.Request = c.Request
	return s.Uman.GetSession() 
}

func (s *Site) Redirect(path string) {
	http.Redirect(s.Uman.Writer, s.Uman.Request, path, 302)
}

func main() {
	site := New()
	site.Uman.Register("admin", "s3cr3t")

	router.GET("/user/:name", func (c *gin.Context) {
		user := c.Param("name")
		session := site.Adapt(c)

		if session.User != user {
			site.Redirect("/")
			return
		}

		c.String(http.StatusOK, "Hello %s", user)
	})

	router.POST("/register", func (c *gin.Context) {
		if session := site.Adapt(c); session.IsLogged() {
			site.Redirect("/" + session.User)
			return
		}

		user, pass, repeat := c.PostForm("user"), c.PostForm("pass"), c.PostForm("repeat")

		result := false
		if pass == repeat  {
			result = site.UM.Register(user, pass)
		}

		if result {
			site.Uman.Login(user, pass)
			site.Redirect("/user/" + user)
		}
	})

	router.POST("/login", func (c *gin.Context) {
		session := site.Adapt(c)
		site.Uman.Login(c.PostForm("user"), c.PostForm("pass"), session)
		
		if !session.IsLogged() {
			site.Redirect("/")
		} else {
			site.Redirect("/user/" + session.User)
		}
		
	})
}
```

## Documentation

API documentation is in progress, for now you may read the code or the examples above.

## License
[GNU Affero General Public License](http://www.gnu.org/licenses/agpl-3.0.html)