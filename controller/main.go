package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"text/template"
	"time"

	//	"github.com/google/uuid"
	//	"github.com/google/uuid"
	"github.com/AbishSowrirajan/Kloudone/models"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type cu models.CreateUsers

type lg models.LoginDetails

type ud models.Uuid

type qu models.Comments

type ry models.Reply

var result models.Reply

type chanel struct {
	Uuid  string
	Error error
}

type post struct {
	Response error
	Uname    string
}

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

func findRoot(uuid string, ctx context.Context, result models.Reply) chan chanel {
	var ch = make(chan chanel)
	var e error
	var mainpost models.Comments

	go func() {

		filter := bson.D{{"uuid", uuid}}

		collection := client.Database("test").Collection("Questions")

		e = collection.FindOne(ctx, filter).Decode(&mainpost)

		rootid := mainpost.Uuid

		if e != nil {

			for {
				fmt.Println(uuid)

				filter := bson.D{{"uuid", uuid}}

				collection := client.Database("test").Collection("Reply")

				e = collection.FindOne(ctx, filter).Decode(&result)

				if e != nil {
					break
				}

				if result.ParentId == result.RootId {

					break
				}
				uuid = result.ParentId

			}
			rootid = result.RootId

		}

		ch <- chanel{rootid, e}
		close(ch)
	}()
	return ch
}

func updateCount(uuid string, ctx context.Context, result models.Reply) chan chanel {

	var ch = make(chan chanel)
	var e error
	var mainpost models.Comments

	uid := uuid
	go func() {

		for {

			fmt.Println("started", uid)

			filter := bson.D{{"uuid", uid}}

			collection := client.Database("test").Collection("Reply")

			e = collection.FindOne(ctx, filter).Decode(&result)

			fmt.Println(e)

			if e != nil {
				break
			}
			filter = bson.D{{"uuid", uid}}

			update := bson.D{
				{"$inc",
					bson.D{
						{"count", 1},
					}},
			}

			_, e := collection.UpdateOne(ctx, filter, update)
			if e != nil {

				break
			}

			if result.ParentId == result.RootId {
				uid = result.ParentId
				break
			}
			uid = result.ParentId

		}
		fmt.Println("Ended", uid, result.ParentId)
		if e != nil || result.ParentId == result.RootId {

			filter := bson.D{{"uuid", uid}}

			collection := client.Database("test").Collection("Questions")

			e = collection.FindOne(ctx, filter).Decode(&mainpost)

			filter = bson.D{{"uuid", uid}}

			update := bson.D{
				{"$inc",
					bson.D{
						{"count", 1},
					}},
			}

			_, e := collection.UpdateOne(ctx, filter, update)
			if e != nil {

				e = errors.New("error in updating count of the document")
			}

		}
		ch <- chanel{result.ParentId, e}
		close(ch)
	}()
	fmt.Println("done", e)

	return ch

}

func sessionManger(w http.ResponseWriter, r *http.Request) (bool, error) {
	_, err := r.Cookie("_zbsid")

	if err != nil {
		log.Println(err)

		return false, err
	}

	vars := mux.Vars(r)

	uname := vars["username"]

	findOptions := options.Find()
	findOptions.SetLimit(10)
	findOptions.SetSort(bson.D{{"posttime", 1}})

	collection := client.Database("test").Collection("Sessions")

	filter := bson.D{{"fname", uname}}

	cur, err := collection.Find(ctx, filter, findOptions)

	var session models.Sessions

	if err != nil {
		log.Println(err)
		err = errors.New("Server Error")

		err = t.ExecuteTemplate(w, "login.gohtml", err)

		return false, err
	}

	for cur.Next(ctx) {

		// create a value into which the single document can be decoded
		err := cur.Decode(&session)
		if err != nil {
			log.Println(err)
			err = errors.New("Server Error")

			err = t.ExecuteTemplate(w, "login.gohtml", err)

			return false, err
		}

	}

	fmt.Println(session)

	if err != nil {
		log.Println(err)

		return false, err
	}

	if session.LoggedIn == false {

		return false, nil
	}

	currenttime := time.Now()
	//s/essiontime := session.Posttime.Minute()

	diff := currenttime.Sub(session.Posttime).Hours()

	if diff > .05 {
		return false, nil
	}

	return true, nil

}
func postquestion(w http.ResponseWriter, r *http.Request) error {

	vars := mux.Vars(r)

	uname := vars["username"]

	po := post{nil, uname}

	valid, err := sessionManger(w, r)

	if valid == false {
		err = errors.New("Please login to continue")
		err = t.ExecuteTemplate(w, "login.gohtml", err)
		return err
	}
	if r.Method == "POST" {

		comment := r.FormValue("comment")

		if len(comment) == 0 {
			err := errors.New("Please post some question")
			po.Response = err
			err = t.ExecuteTemplate(w, "post.gohtml", po)
			return err
		}

		filter := bson.D{{"fname", uname}}

		var result models.CreateUsers

		collection := client.Database("test").Collection("Users")

		err := collection.FindOne(ctx, filter).Decode(&result)

		if err != nil {
			log.Println(err)
			err = errors.New("Server Error")

			err = t.ExecuteTemplate(w, "login.gohtml", err)

			return err
		}
		namespace, _ := uuid.NewRandom()

		UUID := uuid.NewSHA1(namespace, []byte(comment)).String()

		posttime := time.Now().Format("Mon Jan 2 15:04:05")

		question := qu{Fname: result.Fname, Uuid: UUID, Email: result.Email, Question: comment, Posttime: posttime}

		collection = client.Database("test").Collection("Questions")

		_, err = collection.InsertOne(ctx, question)

		if err != nil {
			log.Println(err)
			err = errors.New("Server Error")

			err = t.ExecuteTemplate(w, "login.gohtml", err)

			return err
		}

		po.Response = errors.New("Question has been posted successfully")
		err = t.ExecuteTemplate(w, "post.gohtml", po)
		return err
	}

	err = t.ExecuteTemplate(w, "post.gohtml", po)
	return err
}

func questions(w http.ResponseWriter, r *http.Request) error {

	type q struct {
		Uname   string
		Results []models.Comments
	}
	vars := mux.Vars(r)

	valid, err := sessionManger(w, r)

	if valid == false {
		err = errors.New("Please login to continue")
		err = t.ExecuteTemplate(w, "login.gohtml", err)
		return err
	}

	var data q
	data.Uname = vars["username"]

	findOptions := options.Find()

	collection := client.Database("test").Collection("Questions")

	filter := bson.D{{}}

	cur, err := collection.Find(ctx, filter, findOptions)

	if err != nil {
		log.Println(err)
		err = errors.New("Server Error")

		err = t.ExecuteTemplate(w, "login.gohtml", err)

		return err
	}

	for cur.Next(context.TODO()) {

		// create a value into which the single document can be decoded
		var result models.Comments
		err := cur.Decode(&result)
		if err != nil {
			log.Println(err)
			err = errors.New("Server Error")

			err = t.ExecuteTemplate(w, "login.gohtml", err)

			return err
		}

		data.Results = append(data.Results, result)
	}

	if err := cur.Err(); err != nil {
		log.Println(err)
		err = errors.New("Server Error")

		err = t.ExecuteTemplate(w, "login.gohtml", err)

		return err
	}

	// Close the cursor once finished
	cur.Close(ctx)

	err = t.ExecuteTemplate(w, "comments.gohtml", data)
	return err

}

func postthread(w http.ResponseWriter, r *http.Request) error {

	type replies struct {
		Comment  string
		Count    string
		Fname    string
		Uuid     string
		Posttime string
	}

	type pthread struct {
		Post   string
		Count  string
		Uname  string
		UUID   string
		Thread []replies
	}

	vars := mux.Vars(r)

	uname := vars["username"]

	valid, err := sessionManger(w, r)

	if valid == false {
		err = errors.New("Please login to continue")
		err = t.ExecuteTemplate(w, "login.gohtml", err)
		return err
	}
	uuid := vars["uid"]

	var mainpost models.Comments

	filter := bson.D{{"uuid", uuid}}

	collection := client.Database("test").Collection("Questions")

	err = collection.FindOne(ctx, filter).Decode(&mainpost)

	p := mainpost.Question

	if err != nil {
		log.Println(err)
		err = errors.New("Server Error")

		err = t.ExecuteTemplate(w, "login.gohtml", err)

		return err

	}

	var pt pthread

	pt.Post = p
	pt.Count = strconv.Itoa(int(mainpost.Count))
	pt.Uname = uname
	pt.UUID = uuid

	findOptions := options.Find()

	collection = client.Database("test").Collection("Reply")

	filter = bson.D{{"parentid", uuid}}

	cur, err := collection.Find(ctx, filter, findOptions)

	if err != nil {
		log.Println(err)
		err = errors.New("Server Error")

		err = t.ExecuteTemplate(w, "login.gohtml", err)

		return err

	}

	for cur.Next(ctx) {

		// create a value into which the single document can be decoded

		var th replies
		err := cur.Decode(&result)
		if err != nil {
			log.Println(err)
			err = errors.New("Server Error")

			err = t.ExecuteTemplate(w, "login.gohtml", err)

			return err
		}

		th.Comment = result.Comment
		th.Count = strconv.Itoa(int(result.Count))
		th.Fname = result.Fname
		th.Uuid = result.Uuid
		th.Posttime = result.Posttime

		pt.Thread = append(pt.Thread, th)
	}

	if err := cur.Err(); err != nil {
		log.Println(err)
		err = errors.New("Server Error")

		err = t.ExecuteTemplate(w, "login.gohtml", err)

		return err
	}

	// Close the cursor once finished
	cur.Close(ctx)

	err = t.ExecuteTemplate(w, "postthread.gohtml", pt)
	return err

}

func postcomment(w http.ResponseWriter, r *http.Request) error {

	var results models.Reply

	type replies struct {
		Comment  string
		Count    string
		Fname    string
		Uuid     string
		Posttime string
	}

	type pthread struct {
		Post   string
		Count  string
		Uname  string
		UUID   string
		Thread []replies
	}

	var mainpost models.Comments
	var RootID string

	vars := mux.Vars(r)
	uid := vars["uid"]

	fname := vars["username"]

	valid, err := sessionManger(w, r)

	if valid == false {
		err = errors.New("Please login to continue")
		log.Println(err)
		err = t.ExecuteTemplate(w, "login.gohtml", err)
		return err
	}

	c := findRoot(uid, ctx, result)
	rootID := ""
	for v := range c {

		if v.Error != nil {
			log.Println(v.Error)
			err = errors.New("Server Error")

			err = t.ExecuteTemplate(w, "login.gohtml", err)
			return err
		}
		rootID = v.Uuid

	}

	results.ParentId = uid
	results.RootId = rootID
	results.Fname = fname

	r.ParseForm()

	comment := r.FormValue("comment")

	namespace, _ := uuid.NewRandom()

	UUID := uuid.NewSHA1(namespace, []byte(comment))

	results.Uuid = UUID.String()
	results.Comment = comment
	results.Count = 0
	results.Posttime = time.Now().Format("Mon Jan 2 15:04:05")

	collection := client.Database("test").Collection("Reply")

	_, err = collection.InsertOne(ctx, results)

	if err != nil {
		log.Println(err)
		err = errors.New("Server Error")

		err = t.ExecuteTemplate(w, "login.gohtml", err)

		return err
	}

	c = updateCount(uid, ctx, result)

	for v := range c {
		fmt.Println(v)
		if v.Error != nil {
			log.Println(v.Error)
			err = errors.New("Server Error")

			err = t.ExecuteTemplate(w, "login.gohtml", err)
			return err
		}
		RootID = v.Uuid
	}

	if err != nil {
		log.Println(err)
		err = errors.New("Server Error")

		err = t.ExecuteTemplate(w, "login.gohtml", err)

		return err
	}

	filter := bson.D{{"uuid", RootID}}

	update := bson.D{
		{"$inc",
			bson.D{
				{"count", 1},
			}},
	}

	_, err = collection.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Println(err)
		err = errors.New("Server Error")

		err = t.ExecuteTemplate(w, "login.gohtml", err)
		return err
	}

	filter = bson.D{{"uuid", uid}}

	collection = client.Database("test").Collection("Questions")

	err = collection.FindOne(ctx, filter).Decode(&mainpost)

	p := mainpost.Question
	count := mainpost.Count
	if err != nil {

		filter := bson.D{{"uuid", uid}}

		collection = client.Database("test").Collection("Reply")

		err = collection.FindOne(ctx, filter).Decode(&result)

		if err != nil {
			log.Println(err)
			err = errors.New("Server Error")

			err = t.ExecuteTemplate(w, "login.gohtml", err)
			return err
		}
		p = result.Comment
		count = result.Count

	}

	var pt pthread

	pt.Post = p
	pt.Count = strconv.Itoa(int(count))
	pt.Uname = fname
	pt.UUID = vars["uid"]

	findOptions := options.Find()

	collection = client.Database("test").Collection("Reply")

	filter = bson.D{{"parentid", uid}}

	cur, err := collection.Find(ctx, filter, findOptions)

	if err != nil {
		log.Println(err)
		err = errors.New("Server Error")

		err = t.ExecuteTemplate(w, "login.gohtml", err)

		return err
	}

	for cur.Next(context.TODO()) {

		// create a value into which the single document can be decoded
		var result models.Reply
		var th replies
		err := cur.Decode(&result)
		if err != nil {
			log.Println(err)
			err = errors.New("Server Error")

			err = t.ExecuteTemplate(w, "login.gohtml", err)
			return err
		}
		fmt.Println(result)
		th.Comment = result.Comment
		th.Count = strconv.Itoa(int(result.Count))
		th.Fname = result.Fname
		th.Uuid = result.Uuid
		th.Posttime = result.Posttime

		pt.Thread = append(pt.Thread, th)
	}

	if err := cur.Err(); err != nil {
		log.Println(err)
		err = errors.New("Server Error")

		err = t.ExecuteTemplate(w, "login.gohtml", err)
		return err
	}

	// Close the cursor once finished
	cur.Close(ctx)

	err = t.ExecuteTemplate(w, "postthread.gohtml", pt)
	return err

}

func postreply(w http.ResponseWriter, r *http.Request) error {

	type replies struct {
		Comment  string
		Count    string
		Fname    string
		Uuid     string
		Posttime string
	}

	type pthread struct {
		Post   string
		Count  string
		Uname  string
		UUID   string
		Thread []replies
	}

	vars := mux.Vars(r)

	uname := vars["username"]
	uuid := vars["uid"]

	valid, err := sessionManger(w, r)

	if valid == false {
		err = errors.New("Please login to continue")
		log.Println(err)
		err = t.ExecuteTemplate(w, "login.gohtml", err)
		return err
	}

	filter := bson.D{{"uuid", uuid}}

	collection := client.Database("test").Collection("Reply")

	err = collection.FindOne(ctx, filter).Decode(&result)

	p := result.Comment

	if err != nil {
		log.Println(err)
		err = errors.New("Server Error")

		err = t.ExecuteTemplate(w, "login.gohtml", err)

		return err

	}

	var pt pthread

	pt.Post = p
	pt.Count = strconv.Itoa(int(result.Count))
	pt.Uname = uname
	pt.UUID = uuid

	findOptions := options.Find()

	collection = client.Database("test").Collection("Reply")

	filter = bson.D{{"parentid", uuid}}

	cur, err := collection.Find(ctx, filter, findOptions)

	if err != nil {
		log.Println(err)
		err := errors.New("Server Error")

		err = t.ExecuteTemplate(w, "login.gohtml", err)
		return err

	}

	for cur.Next(ctx) {

		// create a value into which the single document can be decoded

		var th replies
		err := cur.Decode(&result)
		if err != nil {
			return err
		}

		th.Comment = result.Comment
		th.Count = strconv.Itoa(int(result.Count))
		th.Fname = result.Fname
		th.Uuid = result.Uuid
		th.Posttime = result.Posttime

		pt.Thread = append(pt.Thread, th)
	}

	if err := cur.Err(); err != nil {
		log.Println(err)
		err := errors.New("Server Error")

		err = t.ExecuteTemplate(w, "login.gohtml", err)

		return err
	}

	// Close the cursor once finished
	cur.Close(ctx)

	err = t.ExecuteTemplate(w, "postthread.gohtml", pt)
	return err
}
func login(w http.ResponseWriter, r *http.Request) error {

	if r.Method == "POST" {

		re := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

		email := r.FormValue("email")
		pass := r.FormValue("psw")

		if len(email) == 0 || len(pass) == 0 {

			err := errors.New("Error in the input fields")
			log.Println(err)

			err = t.ExecuteTemplate(w, "login.gohtml", err)

			return err

		}

		if re.MatchString(email) == false {

			err := errors.New("Invalid Email format")
			log.Println(err)

			err = t.ExecuteTemplate(w, "login.gohtml", err)

			return err
		}

		filter := bson.D{{"email", email}}

		var result models.CreateUsers

		collection := client.Database("test").Collection("Users")

		err := collection.FindOne(ctx, filter).Decode(&result)

		if err != nil {
			log.Println(err)

			err := errors.New("User is Not registered")

			err = t.ExecuteTemplate(w, "login.gohtml", err)
			return err
		}

		err = bcrypt.CompareHashAndPassword(result.Psw, []byte(pass))

		if err != nil {
			log.Println(err)
			err = errors.New("Password is not correct")
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

		var user models.Uuid

		email = r.FormValue("email")

		filter = bson.D{{"email", email}}

		collection = client.Database("test").Collection("UUID")

		err = collection.FindOne(ctx, filter).Decode(&user)

		if err != nil {
			log.Println(err)
			err := errors.New("User is Not registered")

			err = t.ExecuteTemplate(w, "login.gohtml", err)
			return err
		}

		userid := user.Uuid
		fname := user.Fname
		posttime := time.Now()
		login := true

		namespace, _ := uuid.NewRandom()

		sessionid := uuid.NewSHA1(namespace, []byte(email))

		type ses models.Sessions

		session := ses{SessionId: sessionid.String(), Fname: fname, Uuid: userid, Email: email, Cookies: c.String(), Posttime: posttime, LoggedIn: login}

		collection = client.Database("test").Collection("Sessions")

		_, err = collection.InsertOne(ctx, session)

		if err != nil {
			log.Println(err)
			err := errors.New("User is Not registered")

			err = t.ExecuteTemplate(w, "login.gohtml", err)
			return err
		}

		//http.Redirect(w, r, "/home", http.StatusSeeOther)
		err = t.ExecuteTemplate(w, "menu.gohtml", result.Fname)
		return err
	}

	err := t.ExecuteTemplate(w, "login.gohtml", nil)

	return err

}

func CreateUser(w http.ResponseWriter, r *http.Request) error {

	if r.Method == "POST" {

		r.ParseForm()

		email := r.FormValue("email")
		uname := r.FormValue("fname")

		namespace, _ := uuid.NewRandom()

		UUID := uuid.NewSHA1(namespace, []byte(uname))

		fmt.Println(uname + "" + UUID.String())

		uuid := ud{Email: email, Fname: uname, Uuid: UUID.String()}

		collection := client.Database("test").Collection("UUID")

		_, err := collection.InsertOne(ctx, uuid)

		if err != nil {
			log.Println(err)
			err := errors.New("Server Error")

			err = t.ExecuteTemplate(w, "login.gohtml", err)
			return err
		}

		collection = client.Database("test").Collection("Users")

		pass, err := bcrypt.GenerateFromPassword([]byte(r.FormValue("psw")), bcrypt.MinCost)

		if err != nil {
			log.Println(err)
			err := errors.New("Server Error")

			err = t.ExecuteTemplate(w, "login.gohtml", err)
			return err
		}

		user := cu{Fname: r.FormValue("fname"), Lname: r.FormValue("lname"), Psw: pass, Email: r.FormValue("email")}

		_, err = collection.InsertOne(ctx, user)
		if err != nil {
			log.Println(err)
			err := errors.New("Server Error")

			err = t.ExecuteTemplate(w, "login.gohtml", err)

			return err
		}

		io.WriteString(w, "Successfully registered")

		return nil
	}

	err := t.ExecuteTemplate(w, "login.gohtml", nil)

	if err != nil {

		http.Error(w, "error in login page", 404)

		return err
	}

	return nil
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
	err = t.ExecuteTemplate(w, "login.gohtml", nil)

}

func init() {

	logfile, err := os.Create("../Logs/logs.txt")

	if err != nil {
		panic(err)
	}

	log.SetOutput(logfile)

	t = template.Must(template.ParseGlob("../views/*.gohtml"))

	clientOptions := options.Client().ApplyURI("mongodb://mongo-comment:27017/test")

	ctx, _ = context.WithTimeout(context.Background(), 200*time.Second)

	client, _ = mongo.Connect(ctx, clientOptions)

}

func main() {

	r := mux.NewRouter()

	r.Handle("/login", funcHandler(login))

	r.Handle("/{username}/{uid}/postcomment", funcHandler(postcomment))

	r.Handle("/{username}/postquestion", funcHandler(postquestion))

	r.Handle("/{username}/questions", funcHandler(questions))

	r.Handle("/{username}/question/{uid}", funcHandler(postthread))

	r.Handle("/{username}/question/{uid}/reply", funcHandler(postreply))

	r.Handle("/signup", funcHandler(CreateUser))

	r.Handle("/", funcHandler(home))

	ok := http.ListenAndServe(":8080", r)
	fmt.Println("Web program is executing", ok)

}
