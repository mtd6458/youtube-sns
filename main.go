package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/youtube-sns/migration"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"app"
	"auth"
)

// db variable.
var dbDriver = "sqlite3"
var dbName = "data.sqlite3"

var sessionName = "ytboard-session"
var cs = sessions.NewCookieStore([]byte("secret-key-1234"))

func main() {
	app.Init()

	log.Print("Server listening on http://localhost:8080/")

	/**
	 * routing
	 */
	http.HandleFunc("/", IndexHandler)

	http.HandleFunc("/login", LoginHandler)

	http.HandleFunc("/callback", CallbackHandler)

	http.HandleFunc("/logout", LogoutHandler)

	http.HandleFunc("/top", TopHandler)

	http.HandleFunc("/home", HomeHandler)

	http.HandleFunc("/post", PostHandler)

	http.HandleFunc("/delete-post", DeletePostHandler)

	http.HandleFunc("/tag", TagHandler)

	http.ListenAndServe(":8080", nil)
}

func checkLogin(w http.ResponseWriter, r *http.Request) *migration.User {
	session, _ := app.Store.Get(r, "auth-session")
	profile := session.Values["profile"]
	sid := profile.(map[string]interface{})["sub"]

	db, _ := gorm.Open(dbDriver, dbName)
	defer db.Close()

	var user migration.User
	db.Where("sid = ?", sid.(string)).First(&user)

	if user.ID == 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
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

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	page("index").Execute(w, nil)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {

	// Generate random state
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	state := base64.StdEncoding.EncodeToString(b)

	session, err := app.Store.Get(r, "auth-session")

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["state"] = state
	err = session.Save(r, w)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	authenticator, err := auth.NewAuthenticator()

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authenticator.Config.AuthCodeURL(state), http.StatusTemporaryRedirect)
}

func CallbackHandler(w http.ResponseWriter, r *http.Request) {

	session, err := app.Store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.URL.Query().Get("state") != session.Values["state"] {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	authenticator, err := auth.NewAuthenticator()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	token, err := authenticator.Config.Exchange(context.TODO(), r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("no token found: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	oidcConfig := &oidc.Config{
		ClientID: os.Getenv("AUTH0_CLIENT_ID"),
	}

	idToken, err := authenticator.Provider.Verifier(oidcConfig).Verify(context.TODO(), rawIDToken)

	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Getting now the userInfo
	var profile map[string]interface{}
	if err := idToken.Claims(&profile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["id_token"] = rawIDToken
	session.Values["access_token"] = token.AccessToken
	session.Values["profile"] = profile

	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user := checkLogin(w, r)

	if user.ID == 0 {
		db, _ := gorm.Open(dbDriver, dbName)
		defer db.Close()

		userId := profile["sub"]
		name := profile["name"]

		usr := migration.User{
			Model: gorm.Model{},
			Sid:   userId.(string),
			Name:  name.(string),
		}

		db.Debug().Create(&usr)
		log.Println("create usr")
	}

	// Redirect to logged in page
	http.Redirect(w, r, "/top", http.StatusSeeOther)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {

	domain := os.Getenv("AUTH0_DOMAIN")

	logoutUrl, err := url.Parse("https://" + domain)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	logoutUrl.Path += "/v2/logout"
	parameters := url.Values{}

	var scheme string
	if r.TLS == nil {
		scheme = "http"
	} else {
		scheme = "https"
	}

	returnTo, err := url.Parse(scheme + "://" + r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	parameters.Add("returnTo", returnTo.String())
	parameters.Add("client_id", os.Getenv("AUTH0_CLIENT_ID"))
	logoutUrl.RawQuery = parameters.Encode()

	http.Redirect(w, r, logoutUrl.String(), http.StatusTemporaryRedirect)
}

// top page handler
func TopHandler(w http.ResponseWriter, r *http.Request) {
	session, err := app.Store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	profile := session.Values["profile"]
	name := profile.(map[string]interface{})["name"]

	db, _ := gorm.Open(dbDriver, dbName)
	defer db.Close()

	var postList []migration.Post
	var tagList []migration.Tag

	db.Order("created_at desc").Limit(24).Find(&postList)
	db.Not("name", "").Order("created_at desc").Limit(12).Find(&tagList)

	item := struct {
		Title    string
		UserName string
		PostList []migration.Post
		TagList  []migration.Tag
	}{
		Title:    "Top",
		UserName: name.(string),
		PostList: postList,
		TagList:  tagList,
	}

	er := page("top").Execute(w, item)
	if er != nil {
		log.Fatal(er)
	}
}

// home page handler
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	user := checkLogin(w, r)

	db, _ := gorm.Open(dbDriver, dbName)
	defer db.Close()

	if r.Method == "POST" {
		name := r.PostFormValue("name")

		var tag migration.Tag

		if name != "" {
			db.Where("name = ?", name).First(&tag)

			if tag.Model.ID == 0 {
				saveTagRecord(name, user, db, &tag)
			}
		}

		savePostRecord(r, user, db, &tag)
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

	er := page("home").Execute(w, item)
	if er != nil {
		log.Fatal(er)
	}
}

func savePostRecord(r *http.Request, user *migration.User, db *gorm.DB, tag *migration.Tag) {
	address := r.PostFormValue("address")
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
		Title:   r.PostFormValue("title"),
		UserId:  int(user.Model.ID),
		TagId:   int(tag.Model.ID),
	}

	db.Debug().Create(&post)
}

func saveTagRecord(name string, user *migration.User, db *gorm.DB, tag *migration.Tag) {
	*tag = migration.Tag{
		UserId: int(user.Model.ID),
		Name:   name,
	}

	db.Debug().Create(&tag)
}

// post page handler
func PostHandler(w http.ResponseWriter, r *http.Request) {
	user := checkLogin(w, r)

	pid := r.FormValue("pid")

	db, _ := gorm.Open(dbDriver, dbName)
	defer db.Close()

	if r.Method == "POST" {
		msg := r.PostFormValue("message")
		pId, _ := strconv.Atoi(pid)
		comment := migration.Comment{
			UserId:  int(user.Model.ID),
			PostId:  pId,
			Message: msg,
		}
		db.Debug().Create(&comment)
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

	er := page("post").Execute(w, item)
	if er != nil {
		log.Fatal(er)
	}
}

// delete post handler
func DeletePostHandler(w http.ResponseWriter, r *http.Request) {
	db, _ := gorm.Open(dbDriver, dbName)
	defer db.Close()

	pid := r.FormValue("pid")

	switch r.Method {
	case "POST":
		db.Debug().Delete(migration.Post{}, "id = ?", pid)
	}

  http.Redirect(w, r, "top", http.StatusTemporaryRedirect)
}

// tag page handler
func TagHandler(w http.ResponseWriter, r *http.Request) {
	user := checkLogin(w, r)

	tagId := r.FormValue("tagId")
	db, _ := gorm.Open(dbDriver, dbName)
	defer db.Close()

	if r.Method == "POST" {
		address := r.PostFormValue("address")
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

		if strings.Contains(address, "&t") {
			address = address[:strings.Index(address, "&t")]
		}

		tagId, _ := strconv.Atoi(tagId)
		post := migration.Post{
			UserId:  int(user.Model.ID),
			Address: address,
			Title:   r.PostFormValue("title"),
			TagId:   tagId,
		}
		db.Debug().Create(&post)
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

	er := page("tag").Execute(w, item)
	if er != nil {
		log.Fatal(er)
	}
}
