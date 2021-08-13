package migration

import (
	"github.com/jinzhu/gorm"
)

// User model
type User struct {
	gorm.Model
	Sid  string
	Name string
}

// Post model.
type Post struct {
	gorm.Model
	Address string
	Title   string
	UserId  int
}

// Tag model.
type Tag struct {
	gorm.Model
	UserId int
	Name   string
}

// Comment model.
type Comment struct {
	gorm.Model
	UserId  int
	PostId  int
	Message string
}

// Comment.Join join model.
type CommentJoin struct {
	Comment
	User
	Post
}

// Tag join model.
type TagPost struct {
  gorm.Model
  TagId int
  PostId int
}
