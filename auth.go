package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go-auth-api/db"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/argon2"
)

var jwtKey = []byte("my_secret_key")

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"` // Añadir el rol del usuario a los claims
	jwt.RegisteredClaims
}

const (
	timeCost   = 1         // Tiempo de procesamiento (número de iteraciones)
	memoryCost = 64 * 1024 // Memoria utilizada en KB
	threads    = 4         // Número de threads
	keyLength  = 32        // Longitud del hash generado
	saltLength = 16        // Longitud del salt
)

// Verificar contraseña utilizando Argon2
func verifyHash(password, hash string) bool {
	decodedHash, err := base64.RawStdEncoding.DecodeString(hash)
	if err != nil {
		return false
	}
	salt := decodedHash[:saltLength]
	expectedHash := argon2.IDKey([]byte(password), salt, timeCost, memoryCost, threads, keyLength)
	return bytes.Equal(expectedHash, decodedHash[saltLength:])
}

// Obtener el hash y rol almacenados de la base de datos
func getUserDetails(db *sql.DB, username string) (string, string, error) {
	var storedHash, role string
	query := `SELECT password, role FROM users WHERE username = $1`
	err := db.QueryRow(query, username).Scan(&storedHash, &role)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", nil // No se encontró el usuario
		}
		return "", "", err // Otro tipo de error
	}
	return storedHash, role, nil
}

// Manejo de login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Obtener el hash y rol almacenado
	storedHash, role, err := getUserDetails(db.DB, creds.Username)
	if err != nil {
		http.Error(w, "Error al verificar el usuario", http.StatusInternalServerError)
		return
	}

	// Verificar si el usuario existe y si la contraseña es correcta
	if storedHash == "" || !verifyHash(creds.Password, storedHash) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Generar token JWT que incluya el rol del usuario
	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &Claims{
		Username: creds.Username,
		Role:     role, // Añadir el rol del usuario a los claims
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Establecer cookie del token
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}

// Middleware para proteger endpoints
func ProtectedEndpoint(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tokenStr := cookie.Value
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Bienvenido, %s. Rol: %s", claims.Username, claims.Role)
}
