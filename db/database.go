package db

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func InitDB() {
	// Cambia estos valores según tu configuración de PostgreSQL
	connStr := "postgres://store_user:store_password@localhost/online_store?sslmode=disable"

	var err error
	DB, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Error al conectar a la base de datos:", err)
	}

	err = DB.Ping()
	if err != nil {
		log.Fatal("Error al verificar la conexión a la base de datos:", err)
	}

	fmt.Println("Conexión a la base de datos exitosa")
}
