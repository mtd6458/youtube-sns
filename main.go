package main

import (
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

	/**
	 * routing
	 */
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		index(writer, request)
	})

	http.HandleFunc("/login", func(writer http.ResponseWriter, request *http.Request) {
		login(writer, request)
	})

	http.HandleFunc("/home", func(writer http.ResponseWriter, request *http.Request) {
		home(writer, request)
	})

	http.HandleFunc("/post", func(writer http.ResponseWriter, request *http.Request) {
		post(writer, request)
	})

	http.HandleFunc("/group", func(writer http.ResponseWriter, request *http.Request) {
		group(writer, request)
	})

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
	var groupList []migration.Group

	db.Where("group_id > 0").Order("created_at desc").Limit(12).Find(&postList)
	db.Order("created_at desc").Limit(12).Find(&groupList)

	item := struct {
		Title     string
		Name      string
		Account   string
		PostList  []migration.Post
		GroupList []migration.Group
	}{
		Title:     "Index",
		Name:      user.Name,
		Account:   user.Account,
		PostList:  postList,
		GroupList: groupList,
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
		case "group":
			saveGroupRecord(request, user, db)
		}
	}

	var postList []migration.Post
	var groupList []migration.Group

	db.Where("user_id=?", user.ID).
		Not("address", "").
		Order("created_at desc").
		Limit(12).
		Find(&postList)

	db.Where("user_id=?", user.ID).
		Order("created_at desc").
		Limit(12).
		Find(&groupList)

	headItem := struct {
    UserName  string
  }{
    UserName:  user.Name,
  }

	homeItem := struct {
		Title     string
		PostList  []migration.Post
		GroupList []migration.Group
	}{
		Title:     "Home",
		PostList:  postList,
		GroupList: groupList,
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

func saveGroupRecord(request *http.Request, user *migration.User, db *gorm.DB) {
	group := migration.Group{
		UserId:  int(user.Model.ID),
		Name:    request.PostFormValue("name"),
		Message: request.PostFormValue("message"),
	}

	db.Create(&group)
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
		Name            string
		Account         string
		Post            migration.Post
		CommentJoinList []migration.CommentJoin
	}{
		Title:           "Post",
		Name:            user.Name,
		Account:         user.Account,
		Post:            post,
		CommentJoinList: commentJoinList,
	}

	er := page("post").Execute(writer, item)
	if er != nil {
		log.Fatal(er)
	}
}

// group page handler
func group(writer http.ResponseWriter, request *http.Request) {
	user := checkLogin()

	gid := request.FormValue("gid")
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

		gId, _ := strconv.Atoi(gid)
		post := migration.Post{
			UserId:  int(user.Model.ID),
			Address: address,
			Message: request.PostFormValue("message"),
			GroupId: gId,
		}
		db.Create(&post)
	}

	var group migration.Group
	var postList []migration.Post

	db.Where("id = ?", gid).First(&group)
	db.Order("created_at desc").Model(&group).Related(&postList)

	item := struct {
		Message  string
		Group    migration.Group
		PostList []migration.Post
	}{
		Message:  "Group id=" + gid,
		Group:    group,
		PostList: postList,
	}

	er := page("group").Execute(writer, item)
	if er != nil {
		log.Fatal(er)
	}
}
