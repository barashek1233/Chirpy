package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
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

func validChirpyHandler(w http.ResponseWriter, r *http.Request) {
	type requestStruct struct {
		Body string `json:"body"`
	}

	type responseStruct struct {
		Error string `json:"error"`
		Valid string `json:"valid"`
	}

	decoder := json.NewDecoder(r.Body)
	requestData := requestStruct{}
	err := decoder.Decode(&requestData)
	response := responseStruct{}
	if err != nil {
		response.Error = "Something went wrong"
		responseData, _ := json.Marshal(response)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(responseData)

	}
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
	apiServerrMux.HandleFunc("POST /validate_chirp")
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
