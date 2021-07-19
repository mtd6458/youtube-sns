package main

import (
	"fmt"
	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/youtube-sns/migration"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// db variable.
var dbDriver = "sqlite3"
var dbName = "data.sqlite3"

var sessionName = "ytboard-session"
var cs = sessions.NewCookieStore([]byte("secret-key-1234"))

func main() {
	fmt.Println("http://localhost:8080/")

	/**
	 * routing
	 */
	http.HandleFunc("/", index)

	http.HandleFunc("/login", login)

	http.HandleFunc("/home", home)

	http.HandleFunc("/post", post)

	http.HandleFunc("/tag", tag)

	http.ListenAndServe(":8080", nil)
}

func checkLogin() *migration.User {

	ac := "guest@guest.jp"

	var user migration.User
	db, _ := gorm.Open(dbDriver, dbName)
	defer db.Close()

	db.Where("account = ?", ac).First(&user)

	return &user
}

// get target Template.
func page(fname string) *template.Template {
	templates, _ := template.ParseFiles(
		"templates/"+fname+".html",
		"templates/head.html",
		"templates/foot.html",
	)
	return templates
}

// top page handler
func index(w http.ResponseWriter, rq *http.Request) {
	user := checkLogin()

	db, _ := gorm.Open(dbDriver, dbName)
	defer db.Close()

	var postList []migration.Post
	var tagList []migration.Tag

	db.Where("tag_id > 0").Order("created_at desc").Limit(12).Find(&postList)
	db.Not("name", "").Order("created_at desc").Limit(12).Find(&tagList)

	item := struct {
		Title    string
		UserName string
		PostList []migration.Post
		TagList  []migration.Tag
	}{
		Title:    "Index",
		UserName: user.Name,
		PostList: postList,
		TagList:  tagList,
	}

	er := page("index").Execute(w, item)
	if er != nil {
		log.Fatal(er)
	}
}

func login(w http.ResponseWriter, request *http.Request) {
	item := struct {
		Title   string
		Message string
		Account string
	}{
		Title:   "Login",
		Message: "type your account & password:",
		Account: "",
	}

	if request.Method == "GET" {
		er := page("login").Execute(w, item)
		if er != nil {
			log.Fatal(er)
		}
		return
	}

	if request.Method == "POST" {
		db, _ := gorm.Open(dbDriver, dbName)
		defer db.Close()

		account := request.PostFormValue("account")
		pass := request.PostFormValue("pass")
		item.Account = account

		// check account and password
		var re int
		var user migration.User
		db.Where("account = ? and password = ?", account, pass).Find(&user).Count(&re)

		if re <= 0 {
			item.Message = "Wrong account or password."
			page("login").Execute(w, item)
			return
		}

		// login.
		session, _ := cs.Get(request, sessionName)
		session.Values["login"] = true
		session.Values["account"] = user
		session.Values["name"] = user.Name
		session.Save(request, w)
		http.Redirect(w, request, "/", 302)
	}

	er := page("login").Execute(w, item)
	if er != nil {
		log.Fatal(er)
	}
}

func logout(w http.ResponseWriter, request *http.Request) {
	user := checkLogin()

	session, _ := cs.Get(request, sessionName)
	session.Values["login"] = true
	session.Values["account"] = user
	session.Values["name"] = user.Name
	session.Save(request, w)
	http.Redirect(w, request, "/", 302)
}

// home page handler
func home(writer http.ResponseWriter, request *http.Request) {
	user := checkLogin()

	db, _ := gorm.Open(dbDriver, dbName)
	defer db.Close()

	if request.Method == "POST" {
		switch request.PostFormValue("form") {
		case "post":
			savePostRecord(request, user, db)
		case "tag":
			saveTagRecord(request, user, db)
		}
	}

	var postList []migration.Post
	var tagList []migration.Tag

	db.Where("user_id=?", user.ID).
		Not("address", "").
		Order("created_at desc").
		Limit(12).
		Find(&postList)

	db.Where("user_id=?", user.ID).
		Not("name", "").
		Order("created_at desc").
		Limit(12).
		Find(&tagList)

	item := struct {
		Title    string
		UserName string
		PostList []migration.Post
		TagList  []migration.Tag
	}{
		Title:    "Home",
		UserName: user.Name,
		PostList: postList,
		TagList:  tagList,
	}

	er := page("home").Execute(writer, item)
	if er != nil {
		log.Fatal(er)
	}
}

func savePostRecord(request *http.Request, user *migration.User, db *gorm.DB) {
	address := request.PostFormValue("address")
	address = strings.TrimSpace(address)

	if address == "" || strings.HasPrefix(address, "https://www.youtube.com/") == false {
		return
	}

	if strings.HasPrefix(address, "https://www.youtube.com/watch?v=") {
		address = strings.TrimPrefix(address, "https://www.youtube.com/watch?v=")
	}

	if strings.Contains(address, "&ab_channel") {
		address = address[:strings.Index(address, "&ab_channel")]
	}

	if strings.Contains(address, "&list") {
		address = address[:strings.Index(address, "&list")]
	}

	if strings.Contains(address, "&index") {
		address = address[:strings.Index(address, "&index")]
	}

	post := migration.Post{
		Address: address,
		Message: request.PostFormValue("message"),
		UserId:  int(user.Model.ID),
	}

	db.Create(&post)
}

func saveTagRecord(request *http.Request, user *migration.User, db *gorm.DB) {
	name := request.PostFormValue("name")

	if name == "" {
		return
	}

	tag := migration.Tag{
		UserId:  int(user.Model.ID),
		Name:    request.PostFormValue("name"),
		Message: request.PostFormValue("message"),
	}

	db.Create(&tag)
}

// post page handler
func post(writer http.ResponseWriter, request *http.Request) {
	user := checkLogin()

	pid := request.FormValue("pid")
	db, _ := gorm.Open(dbDriver, dbName)
	defer db.Close()

	if request.Method == "POST" {
		msg := request.PostFormValue("message")
		pId, _ := strconv.Atoi(pid)
		comment := migration.Comment{
			UserId:  int(user.Model.ID),
			PostId:  pId,
			Message: msg,
		}
		db.Create(&comment)
	}

	var post migration.Post
	var commentJoinList []migration.CommentJoin

	db.Where("id = ?", pid).First(&post)
	db.Table("comments").
		Select("comments.*, users.id, users.name").
		Joins("join users on users.id = comments.user_id").
		Where("comments.post_id = ?", pid).
		Order("created_at desc").
		Find(&commentJoinList)

	item := struct {
		Title           string
		UserName        string
		Post            migration.Post
		CommentJoinList []migration.CommentJoin
	}{
		Title:           "Post",
		UserName:        user.Name,
		Post:            post,
		CommentJoinList: commentJoinList,
	}

	er := page("post").Execute(writer, item)
	if er != nil {
		log.Fatal(er)
	}
}

// tag page handler
func tag(writer http.ResponseWriter, request *http.Request) {
	user := checkLogin()

	tagId := request.FormValue("tagId")
	db, _ := gorm.Open(dbDriver, dbName)
	defer db.Close()

	if request.Method == "POST" {
		address := request.PostFormValue("address")
		address = strings.TrimSpace(address)
		if address == "" || strings.HasPrefix(address, "https://www.youtube.com/") == false {
			return
		}

		if strings.HasPrefix(address, "https://www.youtube.com/watch?v=") {
			address = strings.TrimPrefix(address, "https://www.youtube.com/watch?v=")
		}

		if strings.Contains(address, "&ab_channel") {
			address = address[:strings.Index(address, "&ab_channel")]
		}

		if strings.Contains(address, "&list") {
			address = address[:strings.Index(address, "&list")]
		}

		if strings.Contains(address, "&index") {
			address = address[:strings.Index(address, "&index")]
		}

		tagId, _ := strconv.Atoi(tagId)
		post := migration.Post{
			UserId:  int(user.Model.ID),
			Address: address,
			Message: request.PostFormValue("message"),
			TagId:   tagId,
		}
		db.Create(&post)
	}

	var tag migration.Tag
	var postList []migration.Post

	db.Where("id = ?", tagId).First(&tag)
	db.Order("created_at desc").Model(&tag).Related(&postList)

	item := struct {
		Title    string
		UserName string
		Message  string
		Tag      migration.Tag
		PostList []migration.Post
	}{
		Title:    "Tag",
		UserName: user.Name,
		Message:  "Tag id=" + tagId,
		Tag:      tag,
		PostList: postList,
	}

	er := page("tag").Execute(writer, item)
	if er != nil {
		log.Fatal(er)
	}
}
