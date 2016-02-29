package main

import (
	"github.com/niemal/uman"
	"github.com/gin-gonic/gin"
	"net/http"
)

type Callbacks map[string]func(c *gin.Context)

type Site struct {
	Uman       *uman.UserManager
	GetRoutes  Callbacks
	PostRoutes Callbacks
	Engine     *gin.Engine
	Port       string
}

func New() *Site {
	site := &Site{
		Uman: uman.New("my.db"),
		Engine: gin.Default(),
		Port: "8080",
	}

	site.Uman.Register("admin", "test")
	site.Engine.LoadHTMLGlob("templates/*")

	site.GetRoutes = Callbacks{
		"/": func (c *gin.Context) {
			session := site.Adapt(c)
			logged := session.IsLogged()

			var user string
			if logged {
				user = session.User
			} else {
				user = c.Request.UserAgent()
			}

			c.HTML(http.StatusOK, "index.tmpl", gin.H{
				"user": user,
				"logged": logged,
			})
		},

		"/login": func (c *gin.Context) {
			if site.Adapt(c).IsLogged() {
				site.Redirect("/")
				return
			}

			c.HTML(http.StatusOK, "login.tmpl", gin.H{
				"ip": c.Request.RemoteAddr,
			})
		},

		"/register": func (c *gin.Context) {
			if site.Adapt(c).IsLogged() {
				site.Redirect("/")
				return
			}
			
			c.HTML(http.StatusOK, "register.tmpl", gin.H{
				"ip": c.Request.RemoteAddr,
			})
		},

		"/logout": func (c *gin.Context) {
			site.Uman.Logout(site.Adapt(c))
			site.Redirect("/")
		},
	}

	site.PostRoutes = Callbacks{
		"/login": func (c *gin.Context) {
			if session := site.Adapt(c); !session.IsLogged() {
				site.Uman.Login(c.PostForm("user"), c.PostForm("pass"), session)
			}

			site.Redirect("/")
		},

		"/register": func (c *gin.Context) {
			if site.Adapt(c).IsLogged() {
				site.Redirect("/")
				return
			}

			user, pass, repeat := c.PostForm("user"), c.PostForm("pass"), c.PostForm("repeat")

			result := false
			if pass == repeat  {
				result = site.Uman.Register(user, pass)
			}

			c.HTML(http.StatusOK, "register.tmpl", gin.H{
				"user":    user,
				"ip":      c.Request.RemoteAddr,
				"success": result,
			})
		},
	}

	return site
}

func (s *Site) Run() {
	for route, callback := range s.GetRoutes {
		s.Engine.GET(route, callback)
	}

	for route, callback := range s.PostRoutes {
		s.Engine.POST(route, callback)
	}

	s.Engine.Run(":" + s.Port)
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
	site.Run()
}