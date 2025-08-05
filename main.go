package main

import (
	"chirpy/internal/auth"
	"chirpy/internal/database"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
}

type requestStruct struct {
	Body   string `json:"body"`
	UserId string `json:"user_id"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// type validateResponse struct {
// 	CleanedBody string `json:"cleaned_body"`
// }

type User struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

type ChirpResponse struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    string    `json:"user_id"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", cfg.fileserverHits.Load())))
}

func (cfg *apiConfig) resetMetricsHandler(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		respondWithError(w, 403, "error delete all users, have not dev")
		return
	}
	err := cfg.db.DeletAllUsers(r.Context())
	if err != nil {
		respondWithError(w, 400, "failed to delete all users")
		return
	}
	respondWithJSON(w, 200, "OK")
}

func (cfg *apiConfig) apiCheckPassword(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	email := User{}
	err := decoder.Decode(&email)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("failed to parse email and password - %v\n", err))
		return
	}
	hashPass, err := cfg.db.GetHashPassword(r.Context(), email.Email)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintln("Incorrect email or password"))
		return
	}
	err = auth.CheckPasswordHash(email.Password, hashPass)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintln("Incorrect email or password"))
		return
	}
	user, err := cfg.db.GetUserForEmail(r.Context(), email.Email)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintln("Incorrect email or password"))
		return
	}
	respondWithJSON(w, 200, struct {
		ID        string    `json:"id"`
		Email     string    `json:"email"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}{
		ID:        user.ID.String(),
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	})

}

func (cfg *apiConfig) apiCreateUser(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	email := User{}
	err := decoder.Decode(&email)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("failed to parse email and password - %v\n", err))
		return
	}
	hashPass, err := auth.HashPassword(email.Password)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("failed to hash password - %v\n", err))
		return
	}
	user, err := cfg.db.CreateUser(r.Context(), database.CreateUserParams{
		Email:          email.Email,
		HashedPassword: hashPass,
	})
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("failed create user in database - %v\n", err))
		return
	}
	respondWithJSON(w, 201, struct {
		ID        string    `json:"id"`
		Email     string    `json:"email"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}{
		ID:        user.ID.String(),
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	})
}

func (cfg *apiConfig) validChirpyHandler(w http.ResponseWriter, r *http.Request) {

	decoder := json.NewDecoder(r.Body)
	requestData := requestStruct{}
	err := decoder.Decode(&requestData)
	if err != nil {
		respondWithError(w, 400, "Invalid JSON")
		return
	}
	if len(requestData.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long")
		return
	}
	newBody := checkProfaneWords(requestData.Body)
	newChirp, err := cfg.db.CreateChirp(r.Context(), database.CreateChirpParams{Body: newBody, UserID: uuid.MustParse(requestData.UserId)})
	if err != nil {
		respondWithError(w, 400, fmt.Sprint(err))
	}

	respondWithJSON(w, 201, struct {
		Id        string `json:"id"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		Body      string `json:"body"`
		UserId    string `json:"user_id"`
	}{
		Id:        newChirp.ID.String(),
		CreatedAt: newChirp.CreatedAt.String(),
		UpdatedAt: newChirp.UpdatedAt.String(),
		Body:      newChirp.Body,
		UserId:    newChirp.UserID.String(),
	})
}

func (cfg *apiConfig) getAllChirps(w http.ResponseWriter, r *http.Request) {
	chirpId := r.PathValue("chirpID")
	if chirpId != "" {
		chirp, err := cfg.db.GetChirpForId(r.Context(), uuid.MustParse(chirpId))
		if err != nil {
			respondWithError(w, 404, fmt.Sprint(err))
			return
		}
		// if chirp.
		respondWithJSON(w, 200, ChirpResponse{
			ID:        chirp.ID.String(),
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID.String(),
		})
		return
	}
	chirps, err := cfg.db.GetAllChirps(r.Context())
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("%v\n", err))
		return
	}
	respChirps := make([]ChirpResponse, 0, len(chirps))
	for _, item := range chirps {
		respChirps = append(respChirps, ChirpResponse{
			ID:        item.ID.String(),
			CreatedAt: item.CreatedAt,
			UpdatedAt: item.UpdatedAt,
			Body:      item.Body,
			UserID:    item.UserID.String(),
		})
	}
	respondWithJSON(w, 200, respChirps)

}

func healthzHadler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	respondWithJSON(w, code, errorResponse{Error: msg})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	encoder := json.NewEncoder(w)
	encoder.Encode(payload)
}

func checkProfaneWords(str string) string {
	if len(str) == 0 {
		return str
	}
	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}
	slsWords := strings.Split(str, " ")
	for i := range slsWords {
		word := strings.ToLower(slsWords[i])
		for j := range profaneWords {
			if word == profaneWords[j] {
				slsWords[i] = "****"
			}
		}
	}

	return strings.Join(slsWords, " ")
}

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println("error load env - ", err)
		return
	}
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)

	apiCfg := &apiConfig{
		db:       database.New(db),
		platform: os.Getenv("PLATFORM"),
	}
	serverMux := http.NewServeMux()

	fileServer := http.FileServer(http.Dir("."))
	serverMux.Handle("/app/", http.StripPrefix("/app", apiCfg.middlewareMetricsInc(fileServer)))

	adminServerMux := http.NewServeMux()
	adminServerMux.HandleFunc("GET /metrics", apiCfg.metricsHandler)
	adminServerMux.HandleFunc("POST /reset", apiCfg.resetMetricsHandler)
	serverMux.Handle("/admin/", http.StripPrefix("/admin", adminServerMux))

	apiServerrMux := http.NewServeMux()
	apiServerrMux.HandleFunc("GET /healthz", healthzHadler)
	apiServerrMux.HandleFunc("POST /chirps", apiCfg.validChirpyHandler)
	apiServerrMux.HandleFunc("GET /chirps/{chirpID}", apiCfg.getAllChirps)
	apiServerrMux.HandleFunc("POST /users", apiCfg.apiCreateUser)
	apiServerrMux.HandleFunc("POST /login", apiCfg.apiCheckPassword)
	serverMux.Handle("/api/", http.StripPrefix("/api", apiServerrMux))

	server := http.Server{
		Addr:    ":8080",
		Handler: serverMux,
	}

	err = server.ListenAndServe()

	if err != nil {
		fmt.Println(err)
	}
}
