package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"golang.org/x/crypto/argon2"
)

// Estructura para manejar usuarios
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Mapa para almacenar usuarios
var users = make(map[string]string)

// Configuración de parámetros para Argon2
const (
	timeCost   = 1
	memoryCost = 64 * 1024
	threads    = 4
	keyLength  = 32
	saltLength = 16
)

// Generar el hash Argon2 para una contraseña
func generateHash(password string) string {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		log.Fatal(err)
	}
	hash := argon2.IDKey([]byte(password), salt, timeCost, memoryCost, threads, keyLength)
	combined := append(salt, hash...)
	return base64.RawStdEncoding.EncodeToString(combined)
}

// Manejador para registrar un nuevo usuario
func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Verificar si el usuario ya existe
	if _, exists := users[creds.Username]; exists {
		w.WriteHeader(http.StatusConflict) // 409: Conflict
		fmt.Fprintln(w, "El usuario ya existe")
		return
	}

	// Generar hash de la contraseña y almacenar el usuario
	hashedPassword := generateHash(creds.Password)
	users[creds.Username] = hashedPassword

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, "Usuario creado exitosamente")
}
