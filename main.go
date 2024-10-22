package main

import (
	"go-auth-api/db"
	middleware "go-auth-api/http" // Importar el middleware desde la carpeta http
	"log"
	"net/http"
)

func main() {
	// Inicializar base de datos
	db.InitDB()

	// Configurar rutas
	http.HandleFunc("/register", CreateUserHandler)  // Endpoint para registrar usuarios
	http.HandleFunc("/login", LoginHandler)          // Endpoint para login
	http.HandleFunc("/protected", ProtectedEndpoint) // Endpoint protegido general

	// Rutas protegidas por roles específicos
	http.HandleFunc("/admin", middleware.RequireRole("admin"))       // Solo accesible para administradores
	http.HandleFunc("/vendedor", middleware.RequireRole("vendedor")) // Solo accesible para vendedores

	// Iniciar servidor
	log.Println("Servidor corriendo en http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
