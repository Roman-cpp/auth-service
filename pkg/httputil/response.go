package httputil

import (
	"encoding/json"
	"net/http"
)

type Response struct {
	Data any `json:"data"`
}

type PaginationResponse struct {
	Data       any         `json:"data"`
	Pagination *Pagination `json:"pagination"`
}

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Pagination struct {
	Total      int `json:"total"`
	Page       int `json:"page"`
	Limit      int `json:"limit"`
	TotalPages int `json:"total_pages"`
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
