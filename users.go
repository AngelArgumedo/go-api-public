package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"go-auth-api/db"
	"log"
	"net/http"

	"golang.org/x/crypto/argon2"
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"` // Nuevo campo para el rol del usuario
}

// Generar hash de contraseña usando Argon2
func generateHash(password string) string {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		log.Fatal(err)
	}
	hash := argon2.IDKey([]byte(password), salt, timeCost, memoryCost, threads, keyLength)
	combined := append(salt, hash...)
	return base64.RawStdEncoding.EncodeToString(combined)
}

// Manejador para crear usuario con roles
func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Verificar si el usuario ya existe
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)`
	err = db.DB.QueryRow(query, creds.Username).Scan(&exists)
	if err != nil {
		http.Error(w, "Error al verificar el usuario", http.StatusInternalServerError)
		return
	}

	if exists {
		w.WriteHeader(http.StatusConflict) // 409: Conflict
		http.Error(w, "El usuario ya existe", http.StatusConflict)
		return
	}

	// Si no se especifica un rol, asignar el rol por defecto "user"
	if creds.Role == "" {
		creds.Role = "user"
	}

	// Generar hash de la contraseña y almacenar el usuario
	hashedPassword := generateHash(creds.Password)
	insertQuery := `INSERT INTO users (username, password, role) VALUES ($1, $2, $3)`
	_, err = db.DB.Exec(insertQuery, creds.Username, hashedPassword, creds.Role)
	if err != nil {
		log.Println("Error al crear usuario:", err)
		http.Error(w, "Error al crear usuario", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Usuario creado exitosamente"))
}
