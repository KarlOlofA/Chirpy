package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/KarlOlofA/Chirpy/internal/auth"
	"github.com/KarlOlofA/Chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	auth_secret    string
}

var profanity = [...]string{"kerfuffle", "sharbert", "fornax"}

func main() {

	godotenv.Load()

	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)

	if err != nil {
		log.Fatal(err)
	}
	dbQueries := database.New(db)

	conf := apiConfig{
		db:          dbQueries,
		auth_secret: os.Getenv("AUTH_SECRET"),
	}
	mux := http.NewServeMux()

	handler := conf.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir("."))))

	mux.Handle("/app/", handler)
	mux.Handle("/app/assets/", handler)

	mux.HandleFunc("GET /api/healthz", healthCheck)
	mux.HandleFunc("POST /api/users", conf.createUser)
	mux.HandleFunc("POST /api/login", conf.loginUser)
	mux.HandleFunc("POST /api/refresh", conf.refreshApiToken)
	mux.HandleFunc("POST /api/revoke", conf.revokeRefreshToken)
	mux.HandleFunc("GET /api/users", conf.getUserByEmail)
	mux.HandleFunc("PUT /api/users", conf.getUserByEmail)

	mux.HandleFunc("POST /api/chirps", conf.createChirp)
	mux.HandleFunc("GET /api/chirps", conf.getAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirpId}", conf.getChirp)

	mux.HandleFunc("POST /admin/reset", conf.reset)
	mux.HandleFunc("GET /admin/metrics", conf.metrics)

	server := http.Server{
		Handler: mux,
		Addr:    ":8080"}

	server.ListenAndServe()
}

func healthCheck(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Add("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(200)
	writer.Write([]byte("OK\n"))
}

func (cfg *apiConfig) createUser(w http.ResponseWriter, r *http.Request) {
	type userData struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)

	var userD userData
	if err := decoder.Decode(&userD); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed ot read user data")
		return
	}

	hashed_password, err := auth.HashPassword(userD.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	user, err := cfg.db.CreateUser(context.Background(), database.CreateUserParams{Email: userD.Email, HashedPassword: hashed_password})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create user ->%s", err))
		return
	}

	type response struct {
		Id         string    `json:"id"`
		Created_at time.Time `json:"created_at"`
		Updated_at time.Time `json:"updated_at"`
		Email      string    `json:"email"`
	}

	respondWithJSON(w, http.StatusCreated, response{
		Id:         user.ID.String(),
		Created_at: user.CreatedAt,
		Updated_at: user.UpdatedAt,
		Email:      user.Email,
	})
}

func (cfg *apiConfig) getUserByEmail(w http.ResponseWriter, r *http.Request) {
	type userData struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)

	var userD userData
	if err := decoder.Decode(&userD); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed ot read user data")
		return
	}

	user, err := cfg.db.GetUserByEmail(context.Background(), userD.Email)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed ot create user")
		return
	}

	type response struct {
		Id         string    `json:"id"`
		Created_at time.Time `json:"created_at"`
		Updated_at time.Time `json:"updated_at"`
		Email      string    `json:"email"`
	}

	respondWithJSON(w, http.StatusOK, response{
		Id:         user.ID.String(),
		Created_at: user.CreatedAt,
		Updated_at: user.UpdatedAt,
		Email:      user.Email,
	})
}

func (cfg *apiConfig) loginUser(w http.ResponseWriter, r *http.Request) {
	type userData struct {
		Email            string        `json:"email"`
		Password         string        `json:"password"`
		ExpiresInSeconds time.Duration `json:"expires_in_seconds"`
	}

	decoder := json.NewDecoder(r.Body)

	hour := time.Duration(time.Hour * 1)

	var userD userData
	if err := decoder.Decode(&userD); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed ot read user data")
		return
	}

	if userD.ExpiresInSeconds.Seconds() <= 0 {
		userD.ExpiresInSeconds = hour
	}

	user, err := cfg.db.GetUserByEmail(context.Background(), userD.Email)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed ot create user")
		return
	}

	success, err := auth.CompareHash(userD.Password, user.HashedPassword)
	if err != nil || !success {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	jwt, err := auth.MakeJWT(user.ID, cfg.auth_secret, userD.ExpiresInSeconds)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create JWT")
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create Refresh Token")
		return
	}

	expiry := time.Hour * 1440

	rt_params := database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(expiry),
		RevokedAt: sql.NullTime{},
	}

	_, err = cfg.db.CreateRefreshToken(context.Background(), rt_params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to save Refresh Token")
		return
	}

	type response struct {
		Id           string    `json:"id"`
		Created_at   time.Time `json:"created_at"`
		Updated_at   time.Time `json:"updated_at"`
		Email        string    `json:"email"`
		Token        string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
	}

	respondWithJSON(w, http.StatusOK, response{
		Id:           user.ID.String(),
		Created_at:   user.CreatedAt,
		Updated_at:   user.UpdatedAt,
		Email:        user.Email,
		Token:        jwt,
		RefreshToken: refreshToken,
	})
}

func (cfg *apiConfig) refreshApiToken(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Bearer refresh token is invalid.")
		return
	}

	refresh_token, err := cfg.db.GetRefreshToken(context.Background(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Refresh token does not exist.")
		return
	}

	if refresh_token.RevokedAt.Valid {
		respondWithError(w, http.StatusUnauthorized, "Refresh token was revoked.")
		return
	}

	if time.Now().After(refresh_token.ExpiresAt) {
		respondWithError(w, http.StatusUnauthorized, "Refresh token has expired.")
		return
	}

	jwt, err := auth.MakeJWT(refresh_token.UserID, cfg.auth_secret, time.Duration(time.Hour*1))
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create JWT")
		return
	}

	type response struct {
		Token string `json:"token"`
	}

	respondWithJSON(w, http.StatusOK, response{
		Token: jwt,
	})
}

func (cfg *apiConfig) revokeRefreshToken(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Bearer refresh token is invalid.")
		return
	}

	if err = cfg.db.RevokeRefreshToken(context.Background(), token); err != nil {
		respondWithError(w, http.StatusUnauthorized, "Failed to revoke refresh token")
		return
	}

	respondWithError(w, http.StatusNoContent, "Revoked refresh token.")
}

func (cfg *apiConfig) createChirp(w http.ResponseWriter, r *http.Request) {
	type chirpRequest struct {
		Body   string    `json:"body"`
		UserId uuid.UUID `json:"user_id"`
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, fmt.Sprintf("Invalid bearer token -> %s", token))
		return
	}

	uid, err := auth.ValidateJWT(token, cfg.auth_secret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, fmt.Sprintf("Failed to validate JWT -> %s", err))
		return
	}

	decoder := json.NewDecoder(r.Body)
	params := chirpRequest{}
	if err := decoder.Decode(&params); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	if len(params.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	type chirpResponse struct {
		Id        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserId    uuid.UUID `json:"user_id"`
	}

	chirpParams := database.CreatePostParams{
		Body:   params.Body,
		UserID: uid,
	}

	chirp, err := cfg.db.CreatePost(context.Background(), chirpParams)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to add chirp to database -> %s", err))
		return
	}

	respondWithJSON(w, http.StatusCreated, chirpResponse{
		Id:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserId:    chirp.UserID,
	})
}

func (cfg *apiConfig) getAllChirps(w http.ResponseWriter, r *http.Request) {

	chirps, err := cfg.db.GetAllPosts(context.Background())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to fetch chirps from database")
		return
	}

	type chirpResponse struct {
		Id        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserId    uuid.UUID `json:"user_id"`
	}

	items := make([]chirpResponse, len(chirps))

	for i, chirp := range chirps {
		items[i] = chirpResponse{
			Id:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserId:    chirp.UserID,
		}
	}

	respondWithJSON(w, http.StatusOK, items)
}

func (cfg *apiConfig) getChirp(w http.ResponseWriter, r *http.Request) {

	uid, err := uuid.Parse(r.PathValue("chirpId"))
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid uuid")
		return
	}

	chirp, err := cfg.db.GetPost(context.Background(), uid)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Failed to fetch chirp from database")
		return
	}

	type chirpResponse struct {
		Id        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserId    uuid.UUID `json:"user_id"`
	}

	respondWithJSON(w, http.StatusOK, chirpResponse{
		Id:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserId:    chirp.UserID,
	})
}

func (cfg *apiConfig) reset(w http.ResponseWriter, r *http.Request) {
	platform := os.Getenv("PLATFORM")
	if platform != "dev" {
		respondWithError(w, http.StatusForbidden, "Forbidden call.")
		return
	}

	cfg.db.ResetUsers(context.Background())
	cfg.db.ResetPosts(context.Background())
	cfg.fileserverHits.Store(0)
	respondWithJSON(w, http.StatusOK, "Successfully reset contents.")
}

func filterProfanity(msg string) string {
	messages := strings.Split(msg, " ")

	newMessage := []string{}

	for _, word := range messages {
		isProfane := false
		for _, bword := range profanity {
			if strings.ToLower(word) == strings.ToLower(bword) {
				isProfane = true
				break
			}
		}
		if isProfane {
			newMessage = append(newMessage, "****")
		} else {
			newMessage = append(newMessage, word)
		}
	}

	return strings.Join(newMessage, " ")
}

func respondWithError(w http.ResponseWriter, statusCode int, msg string) {
	type chirpError struct {
		Error string `json:"error"`
	}

	error := chirpError{
		Error: msg,
	}

	data, err := json.Marshal(error)
	if err != nil {
		log.Printf("Failed to respond with error")
	}

	w.WriteHeader(statusCode)
	w.Write(data)
}

func respondWithJSON(w http.ResponseWriter, statusCode int, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to parse json payload")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(data)
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cfg.fileserverHits.Add(1)
		fmt.Printf("Hits: %d\n", cfg.fileserverHits.Load())
		next.ServeHTTP(writer, request)
	})
}

func (cfg *apiConfig) metrics(writer http.ResponseWriter, request *http.Request) {

	hits := cfg.fileserverHits.Load()

	writer.WriteHeader(200)
	writer.Header().Add("Content-Type", "text/html")
	writer.Write([]byte(fmt.Sprintf(
		`<html>
		<body>
			<h1>Welcome, Chirpy Admin</h1>
			<p>Chirpy has been visited %d times!</p>
		</body>
	</html>`, hits)))
}
