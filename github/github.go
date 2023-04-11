// Package github provides you access to Github's OAuth2
// infrastructure.
package github

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/golang/glog"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
	oauth2gh "golang.org/x/oauth2/github"
)

// Credentials stores google client-ids.
type Credentials struct {
	ClientID     string `json:"clientid"`
	ClientSecret string `json:"secret"`
}

var (
	conf  *oauth2.Config
	cred  Credentials
	state string
	store sessions.CookieStore
)

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		glog.Fatalf("[Gin-OAuth] Failed to read rand: %v\n", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func Setup(redirectURL, credFile string, scopes []string, secret []byte) {
	store = sessions.NewCookieStore(secret)
	var c Credentials
	file, err := os.ReadFile(credFile)
	if err != nil {
		glog.Fatalf("[Gin-OAuth] File error: %v\n", err)
	}
	err = json.Unmarshal(file, &c)
	if err != nil {
		glog.Fatalf("[Gin-OAuth] Failed to unmarshal client credentials: %v\n", err)
	}
	conf = &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  redirectURL,

		Scopes:   scopes,
		Endpoint: oauth2gh.Endpoint,
	}
}

func Session(name string) gin.HandlerFunc {
	return sessions.Sessions(name, store)
}

func LoginHandler(ctx *gin.Context) {
	state = randToken()
	session := sessions.Default(ctx)
	session.Set("state", state)
	session.Save()

	html := `
	<!DOCTYPE html>
	<html lang="en">

	<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>SSO Login</title>
		<style>
			@import url('https://fonts.googleapis.com/css?family=Poppins');

			/* BASIC */

			html {
				background-color: #56baed;
			}

			body {
				font-family: "Poppins", sans-serif;
				height: 100vh;
			}

			a {
				color: #92badd;
				display: inline-block;
				text-decoration: none;
				font-weight: 400;
			}

			h2 {
				text-align: center;
				font-size: 16px;
				font-weight: 600;
				text-transform: uppercase;
				display: inline-block;
				margin: 40px 8px 10px 8px;
				color: #cccccc;
			}



			/* STRUCTURE */

			.wrapper {
				display: flex;
				align-items: center;
				flex-direction: column;
				justify-content: center;
				width: 100%;
				min-height: 100%;
				padding: 20px;
			}

			.form_data {
				padding-top: 26px;
			}

			#formContent {
				-webkit-border-radius: 10px 10px 10px 10px;
				border-radius: 10px 10px 10px 10px;
				background: #fff;
				padding: 30px;
				width: 90%;
				max-width: 450px;
				position: relative;
				padding: 0px;
				-webkit-box-shadow: 0 30px 60px 0 rgba(0, 0, 0, 0.3);
				box-shadow: 0 30px 60px 0 rgba(0, 0, 0, 0.3);
				text-align: center;
			}



			#formFooter {
				background-color: #f6f6f6;
				border-top: 1px solid #dce8f1;
				padding: 25px;
				text-align: center;
				-webkit-border-radius: 0 0 10px 10px;
				border-radius: 0 0 10px 10px;
			}



			/* TABS */

			h2.inactive {
				color: #cccccc;
			}

			h2.active {
				color: #0d0d0d;
				border-bottom: 2px solid #5fbae9;
			}



			/* FORM TYPOGRAPHY*/

			input[type=button],
			input[type=submit],
			input[type=reset] {
				background-color: #56baed;
				cursor: pointer;
				border: none;
				color: white;
				padding: 15px 80px;
				text-align: center;
				text-decoration: none;
				display: inline-block;
				text-transform: uppercase;
				font-size: 13px;
				-webkit-box-shadow: 0 10px 30px 0 rgba(95, 186, 233, 0.4);
				box-shadow: 0 10px 30px 0 rgba(95, 186, 233, 0.4);
				-webkit-border-radius: 5px 5px 5px 5px;
				border-radius: 5px 5px 5px 5px;
				margin: 5px 20px 40px 20px;
				-webkit-transition: all 0.3s ease-in-out;
				-moz-transition: all 0.3s ease-in-out;
				-ms-transition: all 0.3s ease-in-out;
				-o-transition: all 0.3s ease-in-out;
				transition: all 0.3s ease-in-out;
			}

			input[type=button]:hover,
			input[type=submit]:hover,
			input[type=reset]:hover {
				background-color: #39ace7;
			}

			input[type=button]:active,
			input[type=submit]:active,
			input[type=reset]:active {
				-moz-transform: scale(0.95);
				-webkit-transform: scale(0.95);
				-o-transform: scale(0.95);
				-ms-transform: scale(0.95);
				transform: scale(0.95);
			}

			input[type=text] {
				background-color: #f6f6f6;
				border: none;
				color: #0d0d0d;
				padding: 15px 32px;
				text-align: center;
				text-decoration: none;
				display: inline-block;
				font-size: 16px;
				margin: 5px;
				width: 85%;
				border: 2px solid #f6f6f6;
				-webkit-transition: all 0.5s ease-in-out;
				-moz-transition: all 0.5s ease-in-out;
				-ms-transition: all 0.5s ease-in-out;
				-o-transition: all 0.5s ease-in-out;
				transition: all 0.5s ease-in-out;
				-webkit-border-radius: 5px 5px 5px 5px;
				border-radius: 5px 5px 5px 5px;
			}

			input[type=text]:focus {
				background-color: #fff;
				border-bottom: 2px solid #5fbae9;
			}

			input[type=text]:placeholder {
				color: #cccccc;
			}



			/* ANIMATIONS */

			/* Simple CSS3 Fade-in-down Animation */
			.fadeInDown {
				-webkit-animation-name: fadeInDown;
				animation-name: fadeInDown;
				-webkit-animation-duration: 1s;
				animation-duration: 1s;
				-webkit-animation-fill-mode: both;
				animation-fill-mode: both;
			}

			@-webkit-keyframes fadeInDown {
				0% {
					opacity: 0;
					-webkit-transform: translate3d(0, -100%, 0);
					transform: translate3d(0, -100%, 0);
				}

				100% {
					opacity: 1;
					-webkit-transform: none;
					transform: none;
				}
			}

			@keyframes fadeInDown {
				0% {
					opacity: 0;
					-webkit-transform: translate3d(0, -100%, 0);
					transform: translate3d(0, -100%, 0);
				}

				100% {
					opacity: 1;
					-webkit-transform: none;
					transform: none;
				}
			}

			/* Simple CSS3 Fade-in Animation */
			@-webkit-keyframes fadeIn {
				from {
					opacity: 0;
				}

				to {
					opacity: 1;
				}
			}

			@-moz-keyframes fadeIn {
				from {
					opacity: 0;
				}

				to {
					opacity: 1;
				}
			}

			@keyframes fadeIn {
				from {
					opacity: 0;
				}

				to {
					opacity: 1;
				}
			}

			.fadeIn {
				opacity: 0;
				-webkit-animation: fadeIn ease-in 1;
				-moz-animation: fadeIn ease-in 1;
				animation: fadeIn ease-in 1;

				-webkit-animation-fill-mode: forwards;
				-moz-animation-fill-mode: forwards;
				animation-fill-mode: forwards;

				-webkit-animation-duration: 1s;
				-moz-animation-duration: 1s;
				animation-duration: 1s;
			}

			.fadeIn.first {
				-webkit-animation-delay: 0.4s;
				-moz-animation-delay: 0.4s;
				animation-delay: 0.4s;
			}

			.fadeIn.second {
				-webkit-animation-delay: 0.6s;
				-moz-animation-delay: 0.6s;
				animation-delay: 0.6s;
			}

			.fadeIn.third {
				-webkit-animation-delay: 0.8s;
				-moz-animation-delay: 0.8s;
				animation-delay: 0.8s;
			}

			.fadeIn.fourth {
				-webkit-animation-delay: 1s;
				-moz-animation-delay: 1s;
				animation-delay: 1s;
			}

			/* Simple CSS3 Fade-in Animation */
			.underlineHover:after {
				display: block;
				left: 0;
				bottom: -10px;
				width: 0;
				height: 2px;
				background-color: #56baed;
				content: "";
				transition: width 0.2s;
			}

			.underlineHover:hover {
				color: #0d0d0d;
			}

			.underlineHover:hover:after {
				width: 100%;
			}



			/* OTHERS */

			*:focus {
				outline: none;
			}

			#icon {
				width: 60%;
			}

			* {
				box-sizing: border-box;
			}
		</style>
	</head>

	<body>
		<div class="wrapper fadeInDown">
			<div id="formContent">
				<!-- Tabs Titles -->
				<h2 class="active"> Sign In </h2>
				<form class="form_data">
					<a href="` + GetLoginURL(state) + `">
						<input type="button" class="fadeIn first" value="sign in with github">
					</a>
				</form>
				<div id="formFooter">
					for new user contact admin
				</div>

			</div>
		</div>
	</body>

	</html>
	`
	ctx.Writer.Write([]byte(html))
}

func GetLoginURL(state string) string {
	return conf.AuthCodeURL(state)
}

type AuthUser struct {
	Login   string `json:"login"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Company string `json:"company"`
	URL     string `json:"url"`
}

func init() {
	gob.Register(AuthUser{})
}

func Auth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			ok       bool
			authUser AuthUser
			user     *github.User
		)

		// Handle the exchange code to initiate a transport.
		session := sessions.Default(ctx)
		mysession := session.Get("ginoauthgh")
		if authUser, ok = mysession.(AuthUser); ok {
			ctx.Set("user", authUser)
			ctx.Next()
			return
		}

		retrievedState := session.Get("state")
		if retrievedState != ctx.Query("state") {
			ctx.Redirect(http.StatusTemporaryRedirect, "/login")
			ctx.Abort()
			return
		}

		// TODO: oauth2.NoContext -> context.Context from stdlib
		tok, err := conf.Exchange(oauth2.NoContext, ctx.Query("code"))
		if err != nil {
			ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("Failed to do exchange: %v", err))
			return
		}
		client := github.NewClient(conf.Client(oauth2.NoContext, tok))
		user, _, err = client.Users.Get(oauth2.NoContext, "")
		if err != nil {
			ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("Failed to get user: %v", err))
			return
		}
		// Protection: fields used in userinfo might be nil-pointers
		authUser = AuthUser{
			Login: stringFromPointer(user.Login),
			Name:  stringFromPointer(user.Name),
			URL:   stringFromPointer(user.URL),
		}

		// save userinfo, which could be used in Handlers
		ctx.Set("user", authUser)

		// populate cookie
		session.Set("ginoauthgh", authUser)
		if err := session.Save(); err != nil {
			glog.Errorf("Failed to save session: %v", err)
		}
	}
}

func stringFromPointer(strPtr *string) (res string) {
	if strPtr == nil {
		res = ""
		return res
	}
	res = *strPtr
	return res
}
