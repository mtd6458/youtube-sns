package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/youtube-sns/errors"
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
	if err := Main(); err != nil {
		v := errors.AsAppError(err)
		if v == nil {
			v = errors.AsAppError(errors.Wrap(err))
		}
		fmt.Printf("%+v", v) // or ログ送信等
	}
}

func Main() errors.AppError {
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
	http.HandleFunc("/profile", ProfileHandler)
	http.HandleFunc("/profile-edit", ProfileEditHandler)

	http.ListenAndServe(":8080", nil)

	if err := http.ListenAndServe(":8080", nil); err != nil {
		return errors.Wrap(err)
	}

	return nil
}

func checkLogin(w http.ResponseWriter, r *http.Request) *migration.User {
	session, _ := app.Store.Get(r, "auth-session")
	profile := session.Values["profile"]
	if profile == nil {
		return nil
	}

	db, _ := gorm.Open(dbDriver, dbName)
	defer db.Close()

	var user migration.User

	sid := profile.(map[string]interface{})["sub"]
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
	if user == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if user.ID == 0 {
		db, _ := gorm.Open(dbDriver, dbName)
		defer db.Close()

		userId := profile["sub"]
		name := profile["name"]

		user := migration.User{
			Sid:   userId.(string),
			Name:  name.(string),
		}

		db.Debug().Create(&user)
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
	user := checkLogin(w, r)
	if user == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	name := user.Name

	db, _ := gorm.Open(dbDriver, dbName)
	defer db.Close()

	type Post struct {
		migration.Post
		migration.User
	}

	var postList []Post
	var tagList []migration.Tag

	db.Debug().Table("posts").
		Select("posts.*, users.name").
		Joins("join users on users.id = posts.user_id").
		Order("created_at desc").
		Limit(50).
		Find(&postList)

	db.Not("name", "").
		Order("created_at desc").
		Limit(12).
		Find(&tagList)

	item := struct {
		Title    string
		UserName string
		PostList []Post
		TagList  []migration.Tag
	}{
		Title:    "Top",
		UserName: name,
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
	if user == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	db, _ := gorm.Open(dbDriver, dbName)
	defer db.Close()

	if r.Method == "POST" {
		tagName := r.PostFormValue("tag-name")

		var tag migration.Tag

		if len(tagName) > 0 {
			db.Where("name = ?", tagName).First(&tag)

			if tag.Model.ID == 0 {
				saveTagRecord(tagName, user, db, &tag)
			}
		}

		post, ok := savePostRecord(r, user, db)

		if len(tagName) > 0 && ok {
			tagPost := migration.TagPost{
				TagId:  int(tag.Model.ID),
				PostId: int(post.Model.ID),
			}
			db.Debug().Create(&tagPost)
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

	er := page("home").Execute(w, item)
	if er != nil {
		log.Fatal(er)
	}
}

func savePostRecord(r *http.Request, user *migration.User, db *gorm.DB) (migration.Post, bool) {
	address := r.PostFormValue("address")
	address = strings.TrimSpace(address)

	if address == "" || strings.HasPrefix(address, "https://www.youtube.com/") == false {
		return migration.Post{}, false
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
	}

	db.Debug().Create(&post)

	return post, true
}

func saveTagRecord(tagName string, user *migration.User, db *gorm.DB, tag *migration.Tag) {
	*tag = migration.Tag{
		UserId: int(user.Model.ID),
		Name:   tagName,
	}

	db.Debug().Create(&tag)
}

// post page handler
func PostHandler(w http.ResponseWriter, r *http.Request) {
	user := checkLogin(w, r)
	if user == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

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

	type PostJoinTag struct {
		migration.Post
		migration.Tag
	}

	var postJoinTagList []PostJoinTag
	var commentJoinList []migration.CommentJoin

	db.Debug().Table("posts").
		Select("posts.*, tags.id, tags.name").
		Joins("left join tag_posts on posts.id = tag_posts.post_id").
		Joins("left join tags on tag_posts.tag_id = tags.id").
		Where("posts.id = ?", pid).
		Order("created_at desc").
		Find(&postJoinTagList)

	db.Debug().Table("comments").
		Select("comments.*, users.id, users.name").
		Joins("join users on users.id = comments.user_id").
		Where("comments.post_id = ?", pid).
		Order("created_at desc").
		Find(&commentJoinList)

	tagList := make([]migration.Tag, len(postJoinTagList))
	for i, postJoinTag := range postJoinTagList {
		tagList[i] = postJoinTag.Tag
	}

	item := struct {
		Title           string
		UserName        string
		Post            migration.Post
		IsMyPost        bool
		TagList         []migration.Tag
		CommentJoinList []migration.CommentJoin
	}{
		Title:           "Post",
		UserName:        user.Name,
		Post:            postJoinTagList[0].Post,
		IsMyPost:        int(user.ID) == postJoinTagList[0].Post.UserId,
		TagList:         tagList,
		CommentJoinList: commentJoinList,
	}

	er := page("post").Execute(w, item)
	if er != nil {
		log.Fatal(er)
	}
}

// delete post handler
func DeletePostHandler(w http.ResponseWriter, r *http.Request) {
  user := checkLogin(w, r)
  if user == nil {
    http.Redirect(w, r, "/", http.StatusSeeOther)
    return
  }

	db, _ := gorm.Open(dbDriver, dbName)
	defer db.Close()

	pid := r.FormValue("pid")

	switch r.Method {
	case "POST":
	  var post migration.Post
	  db.Debug().Where("id = ?", pid).First(&post)

    if post.UserId == int(user.ID) {
      db.Debug().Delete(migration.Post{}, "id = ?", pid)
    }
	}

	http.Redirect(w, r, "top", http.StatusTemporaryRedirect)
}

// tag page handler
func TagHandler(w http.ResponseWriter, r *http.Request) {
	user := checkLogin(w, r)
	if user == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

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

		post := migration.Post{
			UserId:  int(user.Model.ID),
			Address: address,
			Title:   r.PostFormValue("title"),
		}

		db.Debug().Create(&post)

		tagId, _ := strconv.Atoi(tagId)
		tagPost := migration.TagPost{
			TagId:  tagId,
			PostId: int(post.ID),
		}

		db.Debug().Create(&tagPost)
	}

	type PostJoinTag struct {
		migration.Post
		migration.Tag
	}

	var postJoinList []PostJoinTag

	db.Debug().Table("posts").
		Select("posts.*, tags.*").
		Joins("left join tag_posts on posts.id = tag_posts.post_id").
		Joins("left join tags on tag_posts.tag_id = tags.id").
		Where("tags.id = ?", tagId).
		Order("created_at desc").
		Find(&postJoinList)

	log.Println(len(postJoinList))

	tag := migration.Tag{}
	if len(postJoinList) > 0 {
		tag = postJoinList[0].Tag
	}

	item := struct {
		Title           string
		UserName        string
		Message         string
		Tag             migration.Tag
		PostJoinTagList []PostJoinTag
	}{
		Title:           "Tag",
		UserName:        user.Name,
		Message:         "Tag id=" + tagId,
		Tag:             tag,
		PostJoinTagList: postJoinList,
	}

	er := page("tag").Execute(w, item)
	if er != nil {
		log.Fatal(er)
	}
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	user := checkLogin(w, r)
	if user == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	item := struct {
		Title    string
		UserName string
	}{
		Title:    "プロフィール",
		UserName: user.Name,
	}

	er := page("profile").Execute(w, item)
	if er != nil {
		log.Fatal(er)
	}
}

func ProfileEditHandler(w http.ResponseWriter, r *http.Request) {
	user := checkLogin(w, r)
	if user == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	db, _ := gorm.Open(dbDriver, dbName)
	defer db.Close()

	name := r.PostFormValue("name")
	if r.Method == "POST" {
		if name != "" {
			db, _ := gorm.Open(dbDriver, dbName)
			defer db.Close()

			db.Debug().Model(&user).Update("name", name)
		}
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
	}

	item := struct {
		Title    string
		UserName string
		UserId   uint
	}{
		Title:    "プロフィール編集",
		UserName: user.Name,
		UserId:   user.Model.ID,
	}

	er := page("profile-edit").Execute(w, item)
	if er != nil {
		log.Fatal(er)
	}
}
