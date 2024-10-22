package main

import (
	"go-auth-api/db"
	"log"
	"net/http"
)

func main() {
	// Inicializar base de datos
	db.InitDB()

	// Configurar rutas
	http.HandleFunc("/register", CreateUserHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/protected", ProtectedEndpoint)

	// Iniciar servidor
	log.Println("Servidor corriendo en http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
