package main

import (
	"github.com/jinzhu/gorm"
	"github.com/youtube-sns/migration"
	"log"
	"net/http"
	"text/template"

	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

// db variable.
var dbDriver = "sqlite3"
var dbName   = "data.sqlite3"

// login check
func checkLogin() *migration.User {

	ac := "taro@yamada.jp"

	var user migration.User
	db, _ := gorm.Open(dbDriver, dbName)
	defer db.Close()

	db.Where("account = ?", ac).First(&user)

	return  &user
}

// get target Template.
func page(fname string) *template.Template {
	tmps, _ := template.ParseFiles("templates/"+fname+".html",
		"templates/head.html", "templates/foot.html")
	return  tmps
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

func main() {

	// index handling
	http.HandleFunc("/", func(w http.ResponseWriter, rq *http.Request) {
		index(w, rq)
	})

	http.ListenAndServe("", nil)
}
