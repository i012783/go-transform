//Predix Transform 2016 Sample

package main

import(
	"log"
	"net/http"
	"fmt"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"golang.org/x/net/context"
	"os"
	"io/ioutil"
	"encoding/base64"
	"strings"
	"net/url"
	"bytes"
	"time"
	"encoding/json"
	_"strconv"
)



const (

	DEBUG =
	EXPIRE_TOKEN = 0

	CLIENT_ID = "app2"
	CLIENT_SECRET = "password"
	SERVICE_CREDENTIAL = "YXBwMjpwYXNzd29yZA=="

	DEFAULT_PORT = "3000"

	htmlIndex = "<html><body><center><div style=\"font-size:50;color:red\">OAuth2 Sample Flow</div><p><p><form method=\"get\" action=\"/login\"><button style=\"font-size:20px;height:50px;width:200px\" type=\"submit\">Auth Flow</button></form></center></body></html>"
	CHECK_TOKEN = "https://aed24829-90b3-4298-b4ab-748041ff5a5e.predix-uaa.run.aws-usw02-pr.ice.predix.io/check_token"
	LOGIN_URL = "https://aed24829-90b3-4298-b4ab-748041ff5a5e.predix-uaa.run.aws-usw02-pr.ice.predix.io/login"
	AUTH_URL = "https://aed24829-90b3-4298-b4ab-748041ff5a5e.predix-uaa.run.aws-usw02-pr.ice.predix.io/oauth/authorize"
	TOKEN_URL = "https://aed24829-90b3-4298-b4ab-748041ff5a5e.predix-uaa.run.aws-usw02-pr.ice.predix.io/oauth/token"
	REDIRECT_URL = "https://go-transform.run.aws-usw02-pr.ice.predix.io/oauth2/callback"

)

/*   OAUTH2 SCOPES   */
var (
	//SCOPES = []string{"engine.read", "engine.write"}
	SCOPES = []string{"engines.read"}
	OAUTH_STATE_STRING = "123456"
)

/*   UAA OAUTH2 ENDPOINTS   */
var  ENDPOINT = oauth2.Endpoint{
	AuthURL:  AUTH_URL,
	TokenURL: TOKEN_URL,
}

/*   Create OAUTH2 configuration client to use in Access Code/Token generation   */
var (
	oauthConf = &oauth2.Config{

		ClientID: 	CLIENT_ID,
		ClientSecret: 	CLIENT_SECRET,
		Scopes:       	SCOPES,
		Endpoint:      	ENDPOINT,
		RedirectURL:    REDIRECT_URL,
	}
)

type MyJWT struct {
	UserName		string 		`json:"user_name"`
	Error 			string 		`json:"error"`
	ErrorDescription	string 		`json:"error_description"`
	Scope			[]string 	`json:"scope"`
}

func Login(w http.ResponseWriter, r *http.Request){

	// AUTHORIZATION_CODE GRANT
	url := oauthConf.AuthCodeURL(OAUTH_STATE_STRING, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusFound)
}


func CallBack(w http.ResponseWriter, r *http.Request) {


	// AUTHORIZATION_CODE GRANT
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if state != OAUTH_STATE_STRING {
		fmt.Fprintf(w, "invalid oauth state, expected '%s', got '%s'\n", OAUTH_STATE_STRING, state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	token, err := oauthConf.Exchange(context.TODO(), code)
		if err !=nil {
			log.Println(err)
			http.Redirect(w, r, "/error?Token Error", http.StatusFound)
			return
		}

	var myJWT MyJWT
	checkToken := CheckToken(token)
	err = json.Unmarshal([]byte(checkToken), &myJWT)
	if err != nil {
		fmt.Printf("Unmarshal error:  %s  ", err)
		os.Exit(31)
	}else if myJWT.ErrorDescription != ""  {
		log.Println(checkToken)
		http.Redirect(w,r, "/error?"+checkToken , http.StatusFound)
		return
	}

	if DEBUG !=0 {

		// PRINT USER JWT
		fmt.Fprintf(w, "<div style=\"width:1200px;word-wrap:break-word;\" NAME=\"SOFT\" WRAP=HARD><div style=\"font-size=50;\" color=\"red\">Raw Token</div></div><br>")
		fmt.Fprintf(w, "<div style=\"width:1200px;word-wrap:break-word;\" NAME=\"SOFT\" WRAP=HARD><div style=\"font-size=20;\" color=\"black\">" + token.AccessToken + "</div></div><br>")

		// DECODE TOKEN
		fmt.Fprintf(w, "<div style=\"width:1200px;word-wrap:break-word;\" NAME=\"SOFT\" WRAP=HARD><div style=\"font-size=50;\" color=\"red\">" + "Decoded Payload" + "</div></div><br>")
		result := strings.Split(token.AccessToken, ".")
		d, _ := base64.StdEncoding.DecodeString(result[1])

		fmt.Fprintf(w, "<div style=\"width:1200px;word-wrap:break-word;font-size:20;color:black\">" + string(d[:len(d)]) + "</div></div><br>")

		fmt.Fprintf(w, "<div style=\"width:1200px;word-wrap:break-word;\" NAME=\"SOFT\" WRAP=HARD><div style=\"font-size=50;\" color=\"red\">" + "Returned from /check_token" + "</div></div><br>")
		fmt.Fprintf(w, checkToken)
	}else {

		fmt.Fprintf(w, "<div style=\"width:1200px;word-wrap:break-word;font-size:30;color:black\">User: " + myJWT.UserName + "</div></div><br>")

		for _, element := range myJWT.Scope {
			//fmt.Fprintf(w, "User Scopes: \"" + element + "\"")
			fmt.Fprintf(w, "<div style=\"width:1200px;word-wrap:break-word;font-size:30;color:black\">Scopes: \"" + element + "\"</div></div><br>")
		}
	}

}

func CheckToken(t *oauth2.Token) (ctr string)  {

	if EXPIRE_TOKEN != 0 {
		//Time delay to check expired token
		time.Sleep(6 * time.Second)
	}

	data := url.Values{}
	data.Set("token", t.AccessToken)

	client := &http.Client{}
	req, err := http.NewRequest("POST", CHECK_TOKEN, bytes.NewBufferString(data.Encode()))
	if err != nil {
		panic(err)
	}

	req.Header.Add("Authorization", "Basic " + SERVICE_CREDENTIAL)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)

	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}

	ctr = string(contents[:len(contents)])

	return ctr
}

func Index(w http.ResponseWriter, r *http.Request){
	fmt.Fprintf(w, htmlIndex)
}

func Error(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "There was an error")
}


func main() {

	var port string
	if port = os.Getenv("PORT"); len(port) == 0 {
		log.Printf("Warning, PORT not set. Defaulting to %+v", DEFAULT_PORT)
		port = DEFAULT_PORT
	}


	mux := mux.NewRouter()
	mux.HandleFunc("/", Index)
	mux.HandleFunc("/login", Login)
	mux.HandleFunc("/oauth2/callback", CallBack)
	mux.HandleFunc("/error", Error)
	http.Handle("/", mux)

	//log.Println("Listening....")

	http.ListenAndServe(":" + port, nil)
}

