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
	secret         string
	polkaKey       string
}

type requestStruct struct {
	Body string `json:"body"`
	// UserId string `json:"user_id"`
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

type ChangeUserEmailPasswd struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type PolkaWebhooks struct {
	Event string    `json:"event"`
	Data  PolkaData `json:"data"`
}

type PolkaData struct {
	UserId string `json:"user_id"`
}

func (cfg *apiConfig) apiPolkaWebhooksPost(w http.ResponseWriter, r *http.Request) {
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintf("%v", err))
		return
	}
	if apiKey != cfg.polkaKey {
		respondWithError(w, 401, "key not valid")
	}
	decoder := json.NewDecoder(r.Body)
	dataFromBody := PolkaWebhooks{}
	err = decoder.Decode(&dataFromBody)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("json err: %v", err))
		return
	}
	if dataFromBody.Event != "user.upgraded" {
		respondWithJSON(w, 204, struct{}{})
		return
	}
	err = cfg.db.UpdgradeToRed(r.Context(), uuid.MustParse(dataFromBody.Data.UserId))
	if err != nil {
		respondWithError(w, 404, fmt.Sprintf("Error update user to red: %v", err))
		return
	}
	respondWithJSON(w, 204, struct{}{})
}

func (cfg *apiConfig) apiDeleteChirps(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintf("Could not find bearer toke: %v", err))
		return
	}
	userId, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		respondWithError(w, 403, fmt.Sprintf("JWT token is not valid: %v", err))
		return
	}
	chirpId := r.PathValue("chirpID")
	chirp, err := cfg.db.GetChirpForId(r.Context(), uuid.MustParse(chirpId))
	if err != nil {
		respondWithError(w, 404, fmt.Sprintf("Chirp is not found: %v", err))
		return
	}
	if chirp.UserID != userId {
		respondWithError(w, 403, "access denied< chirp has not you)")
		return
	}
	err = cfg.db.DeleteChirpForID(r.Context(), chirp.ID)
	if err != nil {
		respondWithError(w, 403, fmt.Sprintf("could not delete chirp: %v", err))
		return
	}
	respondWithJSON(w, 204, struct{}{})

}

func (cfg *apiConfig) apiChangeUsers(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintf("access denied : %v", err))
		return
	}
	userIDFromJWT, errJWTToken := auth.ValidateJWT(token, cfg.secret)

	decoder := json.NewDecoder(r.Body)
	newEmailAndPassword := ChangeUserEmailPasswd{}
	err = decoder.Decode(&newEmailAndPassword)

	if err != nil {
		respondWithError(w, 401, fmt.Sprintf("Could not parse body: %v", err))
		return
	}

	newPass, err := auth.HashPassword(newEmailAndPassword.Password)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintf("did not create hash password: %v", err))
		return
	}

	if errJWTToken != nil {
		respondWithError(w, 401, fmt.Sprintf("Access denied : %v", errJWTToken))
		return
	}
	err = cfg.updateEmailAndPassword(userIDFromJWT, newPass, newEmailAndPassword.Email, r)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintf("could not update email and password from jwt: %v", err))
		return
	}
	respondWithJSON(w, 200, struct {
		Id    uuid.UUID `json:"id"`
		Email string    `json:"email"`
	}{
		Id:    userIDFromJWT,
		Email: newEmailAndPassword.Email,
	})

}

func (cfg *apiConfig) updateEmailAndPassword(userId uuid.UUID, hashedPassword string, newEmail string, r *http.Request) error {
	err := cfg.db.UserUpdateEmail(r.Context(), database.UserUpdateEmailParams{
		ID:    userId,
		Email: newEmail,
	})
	if err != nil {
		return fmt.Errorf("Could not update email: %v", err)
	}
	err = cfg.db.UserUpdatePasswd(r.Context(), database.UserUpdatePasswdParams{
		ID:             userId,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		return fmt.Errorf("could not update password: %v", err)
	}
	return nil
}

func (cfg *apiConfig) apiRevokeToken(w http.ResponseWriter, r *http.Request) {
	bearerToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 400, "missng refresh token")
		return
	}
	err = cfg.db.RevokerefreshToken(r.Context(), bearerToken)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("failed revoke refresh token %v", err))
		return
	}
	respondWithJSON(w, 204, struct{}{})
}

func (cfg *apiConfig) apiRefreshToken(w http.ResponseWriter, r *http.Request) {
	bearerToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "Missing refresh token")
		return
	}

	refreshToken, err := cfg.db.GetRefreshToken(r.Context(), bearerToken)
	if err != nil {
		respondWithError(w, 401, "Invalid refresh token")
		return
	}

	if refreshToken.ExpiresAt.Before(time.Now().UTC()) {
		respondWithError(w, 401, "Refresh token expired")
		return
	}

	if refreshToken.RevokedAt.Valid {
		respondWithError(w, 401, "Refresh token revoked")
		return
	}

	jwtToken, err := auth.MakeJWT(refreshToken.UserID, cfg.secret, time.Hour)
	if err != nil {
		respondWithError(w, 500, "Could not create jwt token")
		return
	}
	respondWithJSON(w, 200, struct {
		Token string `json:"token"`
	}{
		Token: jwtToken,
	})

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

func (cfg *apiConfig) apiLogin(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	req := User{}
	err := decoder.Decode(&req)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("failed to parse email and password - %v\n", err))
		return
	}
	hashPass, err := cfg.db.GetHashPassword(r.Context(), req.Email)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintln("Incorrect email or password"))
		return
	}
	err = auth.CheckPasswordHash(req.Password, hashPass)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintln("Incorrect email or password"))
		return
	}
	user, err := cfg.db.GetUserForEmail(r.Context(), req.Email)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintln("Incorrect email or password"))
		return
	}

	var expiresInSeconds time.Duration = time.Hour
	expiresInSixtyDays := time.Now().Add(time.Hour * 24 * 60)

	token, err := auth.MakeJWT(user.ID, cfg.secret, expiresInSeconds)
	if err != nil {
		respondWithError(w, 500, "Could not create  JWT token")
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, 500, "Could not crate refresh token")
	}

	_, err = cfg.db.CreateToken(r.Context(), database.CreateTokenParams{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: expiresInSixtyDays,
	})

	if err != nil {
		respondWithError(w, 500, "Could not add refresh token to database")
		return
	}

	respondWithJSON(w, 200, struct {
		ID           string    `json:"id"`
		Email        string    `json:"email"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		Token        string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
		IsChirpyRed  bool      `json:"is_chirpy_red"`
	}{
		ID:           user.ID.String(),
		Email:        user.Email,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Token:        token,
		RefreshToken: refreshToken,
		IsChirpyRed:  user.IsChirpyRed,
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
		ID          string    `json:"id"`
		Email       string    `json:"email"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
	}{
		ID:          user.ID.String(),
		Email:       user.Email,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		IsChirpyRed: user.IsChirpyRed,
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
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintf("did not get token: %v", err))
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintf("bad bearer token: %v", err))
		return
	}

	newBody := checkProfaneWords(requestData.Body)
	newChirp, err := cfg.db.CreateChirp(r.Context(), database.CreateChirpParams{Body: newBody, UserID: userID})
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
	s := r.URL.Query().Get("author_id")
	if s != "" {
		chirps, err := cfg.db.GetChirpsFromUserID(r.Context(), uuid.MustParse(s))
		if err != nil {
			respondWithError(w, 400, fmt.Sprintf("could not get chirps from db: %v", err))
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
		secret:   os.Getenv("SECRET"),
		polkaKey: os.Getenv("POLKA_KEY"),
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
	apiServerrMux.HandleFunc("DELETE /chirps/{chirpID}", apiCfg.apiDeleteChirps)
	apiServerrMux.HandleFunc("POST /users", apiCfg.apiCreateUser)
	apiServerrMux.HandleFunc("PUT /users", apiCfg.apiChangeUsers)
	apiServerrMux.HandleFunc("POST /login", apiCfg.apiLogin)
	apiServerrMux.HandleFunc("POST /refresh", apiCfg.apiRefreshToken)
	apiServerrMux.HandleFunc("POST /revoke", apiCfg.apiRevokeToken)
	apiServerrMux.HandleFunc("POST /polka/webhooks", apiCfg.apiPolkaWebhooksPost)
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
