package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

type requestStruct struct {
	Body string `json:"body"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type validateResponse struct {
	CleanedBody string `json:"cleaned_body"`
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
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	cfg.fileserverHits.Store(0)
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

func validChirpyHandler(w http.ResponseWriter, r *http.Request) {

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
	respondWithJSON(w, 200, validateResponse{CleanedBody: checkProfaneWords(requestData.Body)})

}

func main() {
	apiCfg := &apiConfig{}
	serverMux := http.NewServeMux()

	fileServer := http.FileServer(http.Dir("."))
	serverMux.Handle("/app/", http.StripPrefix("/app", apiCfg.middlewareMetricsInc(fileServer)))

	adminServerMux := http.NewServeMux()
	adminServerMux.HandleFunc("GET /metrics", apiCfg.metricsHandler)
	adminServerMux.HandleFunc("POST /reset", apiCfg.resetMetricsHandler)
	serverMux.Handle("/admin/", http.StripPrefix("/admin", adminServerMux))

	apiServerrMux := http.NewServeMux()
	apiServerrMux.HandleFunc("GET /healthz", healthzHadler)
	apiServerrMux.HandleFunc("POST /validate_chirp", validChirpyHandler)
	serverMux.Handle("/api/", http.StripPrefix("/api", apiServerrMux))

	server := http.Server{
		Addr:    ":8080",
		Handler: serverMux,
	}

	err := server.ListenAndServe()

	if err != nil {
		fmt.Println(err)
	}
}
