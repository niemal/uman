package main

import (
	"github.com/gin-gonic/gin"
	"github.com/niemal/uman"
	"net/http"
	"strconv"
)

type callbacks map[string]func(c *gin.Context)

func main() {
	router := gin.Default()
	router.LoadHTMLGlob("templates/*")

	port := "8080"

	um := uman.New("my.db")
	um.Register("admin", "test")

	getRoutes := callbacks{
		"/": func(c *gin.Context) {
			session := um.GetHTTPSession(c.Writer, c.Request)
			logged := session.IsLogged()

			var user string
			if logged {
				user = session.User
			} else {
				user = c.Request.UserAgent()
			}

			c.HTML(http.StatusOK, "index.tmpl", gin.H{
				"user":   user,
				"logged": logged,
			})
		},

		"/login": func(c *gin.Context) {
			session := um.GetHTTPSession(c.Writer, c.Request)

			if session.IsLogged() {
				http.Redirect(c.Writer, c.Request, "/", 302)
				return
			}

			c.HTML(http.StatusOK, "login.tmpl", gin.H{
				"ip": c.Request.RemoteAddr,
			})
		},

		"/register": func(c *gin.Context) {
			session := um.GetHTTPSession(c.Writer, c.Request)

			if session.IsLogged() {
				http.Redirect(c.Writer, c.Request, "/", 302)
				return
			}

			c.HTML(http.StatusOK, "register.tmpl", gin.H{
				"ip": c.Request.RemoteAddr,
			})
		},

		"/logout": func(c *gin.Context) {
			um.GetHTTPSession(c.Writer, c.Request).Logout()
			http.Redirect(c.Writer, c.Request, "/", 302)
		},
	}

	postRoutes := callbacks{
		"/login": func(c *gin.Context) {
			if session := um.GetHTTPSession(c.Writer, c.Request); !session.IsLogged() {
				um.Login(c.PostForm("user"), c.PostForm("pass"), session)

				if session.IsLogged() {
					lifespan, err := strconv.Atoi(c.PostForm("session_lifespan"))

					if err == nil && lifespan > 0 && lifespan < 86401 {
						session.SetLifespan(lifespan)
						session.SetHTTPCookie(c.Writer)
					}
				}
			}

			http.Redirect(c.Writer, c.Request, "/", 302)
		},

		"/register": func(c *gin.Context) {
			if um.GetHTTPSession(c.Writer, c.Request).IsLogged() {
				http.Redirect(c.Writer, c.Request, "/", 302)
				return
			}

			user, pass, repeat := c.PostForm("user"), c.PostForm("pass"), c.PostForm("repeat")

			result := false
			if pass == repeat {
				result = um.Register(user, pass)
			}

			c.HTML(http.StatusOK, "register.tmpl", gin.H{
				"user":    user,
				"ip":      c.Request.RemoteAddr,
				"success": result,
			})
		},
	}

	for route, callback := range getRoutes {
		router.GET(route, callback)
	}

	for route, callback := range postRoutes {
		router.POST(route, callback)
	}

	router.Run(":" + port)
}
