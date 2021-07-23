module github.com/youtube-sns

go 1.13

require (
	app v0.0.0-00010101000000-000000000000
	auth v0.0.0-00010101000000-000000000000
	github.com/coreos/go-oidc v2.1.0+incompatible
	github.com/gorilla/sessions v1.2.1
	github.com/jinzhu/gorm v1.9.16
)

replace app => ./app

replace auth => ./auth
