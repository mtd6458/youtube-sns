module github.com/youtube-sns

go 1.13

require (
	app v0.0.0
	auth v0.0.0-00010101000000-000000000000
	github.com/codegangsta/negroni v1.0.0
	github.com/coreos/go-oidc v2.1.0+incompatible
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/sessions v1.2.1
	github.com/jinzhu/gorm v1.9.16
	github.com/stretchr/testify v1.7.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
	middlewares v0.0.0
)

replace app => ./app

replace auth => ./auth

replace middlewares => ./routes/middlewares
