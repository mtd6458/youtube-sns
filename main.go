package main

import (
  "github.com/jinzhu/gorm"
  "github.com/youtube-sns/migration"
  "html/template"
  "log"
  "net/http"
  "strconv"
  "strings"

  _ "github.com/jinzhu/gorm/dialects/sqlite"
)

// db variable.
var dbDriver = "sqlite3"
var dbName   = "data.sqlite3"

func main() {

  /**
   * routing
   */
  http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
    index(writer, request)
  })

  http.HandleFunc("/home", func(writer http.ResponseWriter, request *http.Request) {
    home(writer, request)
  })

  http.HandleFunc("/post", func(writer http.ResponseWriter, request *http.Request) {
    post(writer, request)
  })

  http.ListenAndServe(":8080", nil)
}

// login check
func checkLogin() *migration.User {

	ac := "guest@guest.jp"

	var user migration.User
	db, _ := gorm.Open(dbDriver, dbName)
	defer db.Close()

	db.Where("account = ?", ac).First(&user)

	return  &user
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
	db.Where("group_id > 0").Order("created_at desc").Limit(10).Find(&postList)

	var groupList []migration.Group
	db.Order("created_at desc").Limit(10).Find(&groupList)

	item := struct {
		Title     string
		Message   string
		Name      string
		Account   string
		PostList  []migration.Post
		GroupList []migration.Group
	}{
		Title:     "Index",
		Message:   "This is Top page.",
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

func home(writer http.ResponseWriter, request *http.Request) {
  user := checkLogin()

  db, _ := gorm.Open(dbDriver, dbName)
  defer db.Close()

  if request.Method == "POST" {
    switch request.PostFormValue("form") {
    case "post":
		savePostRecord(request, user, db)
    }
  }

  var postList []migration.Post

  db.Where("user_id=?", user.ID).Order("created_at desc").Limit(10).Find(&postList)

  item := struct {
    Title string
    Message string
    Name string
    Account string
    PostList []migration.Post
  }{
    Title: "Home",
    Message: "User account=\"" + user.Account +"\".",
    Name: user.Name,
    Account: user.Account,
    PostList: postList,
  }

  er := page("home").Execute(writer, item)
  if er != nil {
    log.Fatal(er)
  }
}

func savePostRecord(request *http.Request, user *migration.User, db *gorm.DB) {
	address := request.PostFormValue("address")
	address = strings.TrimSpace(address)
	if strings.HasPrefix(address, "https://www.youtube.com/watch?v=") {
		address = strings.TrimPrefix(address, "https://www.youtube.com/watch?v=")
	}

	if strings.Contains(address, "&ab_channel") {
		address = address[:strings.Index(address, "&ab_channel")]
	}

	post := migration.Post{
		Address: address,
		Message: request.PostFormValue("message"),
		UserId:  int(user.Model.ID),
	}

	db.Create(&post)
}

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
  var commentJoin []migration.CommentJoin

  db.Where("id = ?", pid).First(&post)
  db.Table("comments").
    Select("comments.*, users.id, users.name").
    Joins("join users on users.id = comments.user_id").
    Where("comments.post_id = ?", pid).
    Order("created_at desc").
    Find(&commentJoin)

  item := struct {
    Title string
    Name string
    Account string
    Post migration.Post
    CommentJoin []migration.CommentJoin
  }{
    Title: "Post",
    Name: user.Name,
    Account: user.Account,
    Post: post,
    CommentJoin: commentJoin,
  }

  er := page("post").Execute(writer, item)
  if er != nil {
    log.Fatal(er)
  }
}
