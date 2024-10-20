package main

import (
	"log"
	"net/http"
)

func main() {
	// Define las rutas para la API
	http.HandleFunc("/login", LoginHandler)          // Ruta para iniciar sesión y obtener JWT
	http.HandleFunc("/protected", ProtectedEndpoint) // Ruta protegida que requiere JWT válido

	// Inicia el servidor en el puerto 8080
	log.Println("Servidor iniciado en http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
