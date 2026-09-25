package httpx

import (
	"encoding/json"
	"net/http"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
)

type Response struct {
	Data any  `json:"data"`
	Meta Meta `json:"meta"`
}

type PaginationResponse struct {
	Data       any         `json:"data"`
	Pagination *Pagination `json:"pagination"`
	Meta       Meta        `json:"meta"`
}

type ErrorResponse struct {
	Error ErrorBody `json:"error"`
	Meta  Meta      `json:"meta"`
}

type ErrorBody struct {
	Code       string         `json:"code"`
	Message    string         `json:"message"`
	Details    map[string]any `json:"details,omitempty"`
	Violations []Violation    `json:"violations,omitempty"`
}

type Meta struct {
	RequestID string `json:"request_id,omitempty"`
	Timestamp string `json:"timestamp"`
}

type Violation struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Pagination struct {
	Page       int    `json:"page"`
	PerPage    int    `json:"per_page"`
	TotalItems int    `json:"total_items"`
	TotalPages int    `json:"total_pages"`
	Sort       string `json:"sort"`
}

// NewMeta собирает meta ответа. request_id берётся из chimw.RequestID —
// по нему ответ клиента находится в логах.
func NewMeta(r *http.Request) Meta {
	return Meta{
		RequestID: chimw.GetReqID(r.Context()),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

func WriteData(w http.ResponseWriter, r *http.Request, status int, data any) {
	WriteJSON(w, status, Response{Data: data, Meta: NewMeta(r)})
}

func WriteError(w http.ResponseWriter, r *http.Request, status int, body ErrorBody) {
	WriteJSON(w, status, ErrorResponse{Error: body, Meta: NewMeta(r)})
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
