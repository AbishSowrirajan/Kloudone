package main

import (
	"Kloudone/models"
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

	"golang.org/x/crypto/bcrypt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
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

	//c := make(chan int)
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

func postquestion(w http.ResponseWriter, r *http.Request) error {

	vars := mux.Vars(r)

	uname := vars["username"]

	po := post{nil, uname}

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
			return err
		}

		po.Response = errors.New("Question has been posted successfully")
		err = t.ExecuteTemplate(w, "post.gohtml", po)
		//http.Error(w, "error in login page", 404)
		return err
	}

	err := t.ExecuteTemplate(w, "post.gohtml", po)
	return err
}

func questions(w http.ResponseWriter, r *http.Request) error {

	type q struct {
		Uname   string
		Results []models.Comments
	}
	vars := mux.Vars(r)

	var data q
	data.Uname = vars["username"]
	//var results []models.Comments

	findOptions := options.Find()

	collection := client.Database("test").Collection("Questions")

	filter := bson.D{{}}

	cur, err := collection.Find(ctx, filter, findOptions)

	if err != nil {

		return err
	}

	for cur.Next(context.TODO()) {

		// create a value into which the single document can be decoded
		var result models.Comments
		err := cur.Decode(&result)
		if err != nil {
			return err
		}

		data.Results = append(data.Results, result)
	}

	if err := cur.Err(); err != nil {
		return err
	}

	// Close the cursor once finished
	cur.Close(ctx)

	err = t.ExecuteTemplate(w, "comments.gohtml", data)
	fmt.Println(err)
	//http.Error(w, "error in login page", 404)
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
	uuid := vars["uid"]

	fmt.Println(uname, uuid)

	var mainpost models.Comments

	filter := bson.D{{"uuid", uuid}}

	collection := client.Database("test").Collection("Questions")

	err := collection.FindOne(ctx, filter).Decode(&mainpost)

	p := mainpost.Question

	fmt.Println(p)

	if err != nil {

		return err

	}

	var pt pthread

	pt.Post = p
	pt.Count = strconv.Itoa(int(mainpost.Count))
	pt.Uname = uname
	pt.UUID = uuid

	//var results []models.Reply

	findOptions := options.Find()

	collection = client.Database("test").Collection("Reply")

	filter = bson.D{{"parentid", uuid}}

	cur, err := collection.Find(ctx, filter, findOptions)

	fmt.Println(err)
	if err != nil {

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
		return err
	}

	fmt.Println(pt)

	// Close the cursor once finished
	cur.Close(context.TODO())

	err = t.ExecuteTemplate(w, "postthread.gohtml", pt)
	//http.Error(w, "error in login page", 404)
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
	fmt.Println(uid)
	fname := vars["username"]

	c := findRoot(uid, ctx, result)
	rootID := ""
	for v := range c {

		if v.Error != nil {
			return v.Error
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

	_, err := collection.InsertOne(ctx, results)

	if err != nil {
		log.Println(err)
		return err
	}

	c = updateCount(uid, ctx, result)

	for v := range c {
		fmt.Println(v)
		if v.Error != nil {
			return v.Error
		}
		RootID = v.Uuid
	}

	fmt.Println("returned from go routuine")
	if err != nil {

		return errors.New("Server Error ")
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
		return err
	}

	//err = updateResult.Decode(&mainpost)

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
			return err
		}
		p = result.Comment
		count = result.Count

	}

	var pt pthread

	fmt.Println(count, strconv.Itoa(int(count)))

	pt.Post = p
	pt.Count = strconv.Itoa(int(count))
	pt.Uname = fname
	pt.UUID = vars["uid"]

	//var results []models.Reply

	findOptions := options.Find()

	collection = client.Database("test").Collection("Reply")

	filter = bson.D{{"parentid", uid}}

	cur, err := collection.Find(ctx, filter, findOptions)

	if err != nil {

		return err
	}

	for cur.Next(context.TODO()) {

		// create a value into which the single document can be decoded
		var result models.Reply
		var th replies
		err := cur.Decode(&result)
		if err != nil {
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
		return err
	}

	fmt.Println(pt)

	// Close the cursor once finished
	cur.Close(context.TODO())

	err = t.ExecuteTemplate(w, "postthread.gohtml", pt)
	//http.Error(w, "error in login page", 404)
	return err

}

func postreply(w http.ResponseWriter, r *http.Request) error {

	//var results models.Reply

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

	fmt.Println(uname, uuid)

	//var mai models.Reply

	filter := bson.D{{"uuid", uuid}}

	collection := client.Database("test").Collection("Reply")

	err := collection.FindOne(ctx, filter).Decode(&result)

	p := result.Comment

	if err != nil {

		return err

	}

	var pt pthread

	pt.Post = p
	pt.Count = strconv.Itoa(int(result.Count))
	pt.Uname = uname
	pt.UUID = uuid

	//var results []models.Reply

	findOptions := options.Find()

	collection = client.Database("test").Collection("Reply")

	filter = bson.D{{"parentid", uuid}}

	cur, err := collection.Find(ctx, filter, findOptions)

	fmt.Println(err)
	if err != nil {

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
		return err
	}

	fmt.Println(pt)

	// Close the cursor once finished
	cur.Close(context.TODO())

	err = t.ExecuteTemplate(w, "postthread.gohtml", pt)
	//http.Error(w, "error in login page", 404)
	return err
}
func login(w http.ResponseWriter, r *http.Request) error {

	//fmt.Println(r.Method)

	if r.Method == "POST" {

		re := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

		email := r.FormValue("email")
		pass := r.FormValue("psw")

		if len(email) == 0 || len(pass) == 0 {

			return errors.New("Error in the input fields")

			//io.WriteString(w, "Error in input value")
		}

		if re.MatchString(email) == false {

			return errors.New("Invalid Email format")
		}

		filter := bson.D{{"email", email}}

		var result models.CreateUsers

		collection := client.Database("test").Collection("Users")

		err := collection.FindOne(ctx, filter).Decode(&result)

		if err != nil {

			err = t.ExecuteTemplate(w, "login.gohtml", err)
			return err
		}

		err = bcrypt.CompareHashAndPassword(result.Psw, []byte(pass))
		fmt.Println(result.Psw, []byte(pass), err)

		if err != nil {
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

		uname := r.FormValue("email")

		namespace, _ := uuid.NewRandom()

		UUID := uuid.NewSHA1(namespace, []byte(uname))

		fmt.Println(uname + "" + UUID.String())

		uuid := ud{Email: uname, Uuid: UUID.String()}

		collection := client.Database("test").Collection("UUID")

		_, err := collection.InsertOne(ctx, uuid)

		if err != nil {
			log.Println(err)
			return err
		}

		collection = client.Database("test").Collection("Users")

		pass, err := bcrypt.GenerateFromPassword([]byte(r.FormValue("psw")), bcrypt.MinCost)

		if err != nil {
			return err
		}

		user := cu{Fname: r.FormValue("fname"), Lname: r.FormValue("lname"), Psw: pass, Email: r.FormValue("email")}

		_, err = collection.InsertOne(ctx, user)
		if err != nil {
			log.Fatal(err)
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
