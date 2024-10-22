package http

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte("my_secret_key")

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Middleware para proteger rutas basadas en roles
func RequireRole(role string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		// Verificar si el rol del usuario coincide con el rol requerido
		if claims.Role != role {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Acceso denegado: no tienes permisos para acceder a esta ruta"))
			return
		}

		// Si todo está bien, continuar con la solicitud
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Acceso concedido"))
	}
}
