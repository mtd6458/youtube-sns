package migration

import (
	"fmt"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

// Migrate program.
func Migrate() {

	// データベースをオープン
	// 変数1, 変数2 := gorm.Open( ドライバ名 , データベース名 )
	// 変数1にはGORMに用意されているDB構造体が格納される
	db, er := gorm.Open("sqlite3", "data.sqlite3")

	if er != nil {
		fmt.Println(er)
		return
	}

	defer db.Close()

	// DB構造体からマイグレーション実行用のメソッドを呼び出す
	// 引数にはマイグレーションするモデルの構造体の値をポインタで渡す。
	// いくつでも指定できる。
	db.AutoMigrate(&User{}, &Tag{}, &Post{}, &Comment{})
}
