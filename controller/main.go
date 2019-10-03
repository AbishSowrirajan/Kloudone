package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"text/template"
	"time"
	"web/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

var orgs = []string{"Xendit", "Paypal", "Mastercard", "Visa"}

type cu models.CreateUsers

type lg models.LoginDetails

type ud models.Uuid

type ClientError interface {
	Error() string
	// ResponseBody returns response body.
	ResponseBody() ([]byte, error)
	// ResponseHeaders returns http status code and headers.
	ResponseHeaders() (int, map[string]string)
}

func home(w http.ResponseWriter, r *http.Request) error {

	err := t.ExecuteTemplate(w, "login.gohtml", nil)

	if err != nil {

		http.Error(w, "error in login page", 404)

	}

	return err
}

func login(w http.ResponseWriter, r *http.Request) error {

	//fmt.Println(r.Method)

	if r.Method == "POST" {

		email := r.FormValue("email")
		pass := r.FormValue("psw")

		if len(email) == 0 || len(pass) == 0 {

			io.WriteString(w, "Error in input value")
		}

		fmt.Println(email)
		filter := bson.D{{"email", email}}

		var result models.CreateUsers

		collection := client.Database("test").Collection("Users")

		err := collection.FindOne(ctx, filter).Decode(&result)

		if err != nil {

			//message := "User is not registered"

			err = t.ExecuteTemplate(w, "login.gohtml", err)
			return err
		}

		c, err := r.Cookie("_zbsid")

		if err != nil {
			id, _ := uuid.NewRandom()
			c = &http.Cookie{
				Name:     "_zbsid",
				Value:    id.String(),
				HttpOnly: true,
			}
			http.SetCookie(w, c)

		}

		//w.Header().Set("location", "/orgs")
		//w.WriteHeader(http.StatusSeeOther)
		err = t.ExecuteTemplate(w, "index.gohtml", nil)
		return err
	}

	err := t.ExecuteTemplate(w, "login.gohtml", nil)

	return err

}

func CreateUser(w http.ResponseWriter, r *http.Request) error {

	//fmt.Println(r.Method)

	if r.Method == "POST" {

		r.ParseForm()

		uname := r.FormValue("email")

		namespace, _ := uuid.NewRandom()

		UUID := uuid.NewSHA1(namespace, []byte(uname))

		//var body cu

		//body, _ = ioutil.ReadAll(r.Body)

		//json.Marshal(r.body)

		fmt.Println(uname + "" + UUID.String())

		uuid := ud{Email: uname, Uuid: UUID.String()}

		collection := client.Database("test").Collection("UUID")

		_, err := collection.InsertOne(ctx, uuid)

		if err != nil {
			log.Fatal(err)
		}

		collection = client.Database("test").Collection("Users")

		user := cu{Fname: r.FormValue("fname"), Lname: r.FormValue("lname"), Psw: []byte(r.FormValue("psw")), Email: r.FormValue("email")}

		_, err = collection.InsertOne(ctx, user)
		if err != nil {
			log.Fatal(err)
		}

		//fmt.Println(": ", insertResult.InsertedID)

		io.WriteString(w, "Successfully registered")

		//http.Redirect(w, r, "/orgs", http.StatusSeeOther)
		return err
	}

	err := t.ExecuteTemplate(w, "login.gohtml", nil)

	if err != nil {

		http.Error(w, "error in login page", 404)

		return err
	}

	return err
}

var t *template.Template

var ctx context.Context

var client *mongo.Client

type funcHandler func(http.ResponseWriter, *http.Request) error

func (methods funcHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := methods(w, r)
	if err == nil {
		return
	}

	log.Printf("An error accured: %v", err)

	clientError, ok := err.(ClientError)
	if !ok {
		w.WriteHeader(500)
		return
	}

	body, err := clientError.ResponseBody()
	if err != nil {
		log.Printf("An error accured: %v", err)
		w.WriteHeader(500)
		return
	}
	status, headers := clientError.ResponseHeaders()
	for k, v := range headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(status)
	w.Write(body)
}

func init() {

	logfile, err := os.Create("../Logs/logs.txt")

	if err != nil {
		panic(err)
	}

	log.SetOutput(logfile)

	t = template.Must(template.ParseGlob("../views/*.gohtml"))

	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")

	ctx, _ = context.WithTimeout(context.Background(), 200*time.Second)

	client, _ = mongo.Connect(ctx, clientOptions)

}

func main() {

	r := mux.NewRouter()

	r.Handle("/login", funcHandler(login))

	r.Handle("/signup", funcHandler(CreateUser))

	r.Handle("/", funcHandler(home))

	ok := http.ListenAndServe(":8080", r)
	fmt.Println("Web program is executing", ok)

}
