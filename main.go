package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/register", CreateUserHandler)  // Nueva ruta para registrar usuarios
	http.HandleFunc("/login", LoginHandler)          // Ruta para iniciar sesión
	http.HandleFunc("/protected", ProtectedEndpoint) // Ruta protegida que requiere autenticación

	log.Println("Servidor iniciado en http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
