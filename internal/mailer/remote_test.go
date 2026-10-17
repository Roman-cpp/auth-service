package mailer_test

import (
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/mailer"
)

const secret = "0123456789abcdef0123456789abcdef"

// Golden-вектор формата подписи. Тот же вектор проверяется в mail-service
// (internal/middleware/apikey): если один из тестов упал, формат разошёлся.
func TestSignGoldenVector(t *testing.T) {
	body := `{"template":"auth.code","to":"a@b.c","data":{"purpose":"login","code":"123456","ttl_minutes":10}}`
	got := hex.EncodeToString(mailer.Sign([]byte(secret), "1700000000", "POST", "/api/v1/messages", []byte(body)))
	const want = "07cd317533838df95b601a124a67e33d8af29776400c36b14f52ad415e1990dd"
	if got != want {
		t.Fatalf("signature = %s, want %s", got, want)
	}
}

// fakeMailService проверяет запрос так же, как настоящий mail-service:
// подпись по секрету, путь, тело. Отвечает по сценарию из respond.
func fakeMailService(t *testing.T, respond func(n int32, w http.ResponseWriter)) (*httptest.Server, *atomic.Int32, *[]byte) {
	t.Helper()
	var calls atomic.Int32
	var lastBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		lastBody = body

		if r.URL.Path != "/api/v1/messages" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-Api-Key") != "auth" || r.Header.Get("Idempotency-Key") != "code-1" {
			t.Errorf("headers: key=%q idem=%q", r.Header.Get("X-Api-Key"), r.Header.Get("Idempotency-Key"))
		}
		want := hex.EncodeToString(mailer.Sign([]byte(secret), r.Header.Get("X-Timestamp"), r.Method, r.URL.Path, body))
		if r.Header.Get("X-Signature") != want {
			t.Errorf("signature mismatch")
		}
		respond(n, w)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls, &lastBody
}

func newRemote(t *testing.T, url string) *mailer.RemoteMailer {
	t.Helper()
	m, err := mailer.NewRemote(config.MailConfig{
		Transport:  config.MailTransportHTTP,
		ServiceURL: url,
		ClientID:   "auth",
		Secret:     secret,
		Timeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("new remote: %v", err)
	}
	return m
}

func TestRemoteSendsSignedTemplateRequest(t *testing.T) {
	srv, calls, lastBody := fakeMailService(t, func(_ int32, w http.ResponseWriter) {
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"data":{"id":"x","status":"queued"}}`))
	})

	err := newRemote(t, srv.URL).SendCode(t.Context(), "u@example.com", auth.CodePurposePasswordReset, "482913", 10*time.Minute, "code-1")
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}

	var req struct {
		Template string `json:"template"`
		To       string `json:"to"`
		Data     struct {
			Purpose    string `json:"purpose"`
			Code       string `json:"code"`
			TTLMinutes int    `json:"ttl_minutes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(*lastBody, &req); err != nil {
		t.Fatalf("body: %v", err)
	}
	if req.Template != "auth.code" || req.To != "u@example.com" ||
		req.Data.Purpose != "password_reset" || req.Data.Code != "482913" || req.Data.TTLMinutes != 10 {
		t.Fatalf("request = %+v", req)
	}
}

// Повтор с тем же ключом почтовик подтверждает 200 — для нас это успех.
func TestRemoteAcceptsReplay(t *testing.T) {
	srv, _, _ := fakeMailService(t, func(_ int32, w http.ResponseWriter) {
		w.WriteHeader(http.StatusOK)
	})
	if err := newRemote(t, srv.URL).SendCode(t.Context(), "u@example.com", auth.CodePurposeMFALogin, "1", time.Minute, "code-1"); err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestRemoteRetriesOnceOn5xx(t *testing.T) {
	srv, calls, _ := fakeMailService(t, func(n int32, w http.ResponseWriter) {
		if n == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	if err := newRemote(t, srv.URL).SendCode(t.Context(), "u@example.com", auth.CodePurposeMFALogin, "1", time.Minute, "code-1"); err != nil {
		t.Fatalf("send: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}
}

// 4xx — ошибка в запросе, повтор бессмыслен; текст почтовика уходит в ошибку,
// чтобы по логу было понятно, что чинить.
func TestRemoteDoesNotRetry4xx(t *testing.T) {
	srv, calls, _ := fakeMailService(t, func(_ int32, w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":{"code":"invalid_template_data","message":"некорректные поля: ttl_minutes"}}`))
	})
	err := newRemote(t, srv.URL).SendCode(t.Context(), "u@example.com", auth.CodePurposeMFALogin, "1", time.Minute, "code-1")
	if err == nil || !strings.Contains(err.Error(), "invalid_template_data") {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
}

func TestRemoteJoinsBasePath(t *testing.T) {
	m := newRemote(t, "https://mail.example.com/prefix/")
	_ = m
	// Путь проверяется через реальный запрос: сервер ниже ожидает /prefix/api/v1/messages.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/prefix/api/v1/messages" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	if err := newRemote(t, srv.URL+"/prefix/").SendCode(t.Context(), "u@example.com", auth.CodePurposeMFALogin, "1", time.Minute, ""); err != nil {
		t.Fatalf("send: %v", err)
	}
}

// Почтовик с сертификатом своего CA (режим internal): без MAIL_CA_FILE
// клиент отвергает его, с файлом — ходит.
func TestRemoteTrustsOnlyPinnedCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	send := func(caFile string) error {
		m, err := mailer.NewRemote(config.MailConfig{
			Transport: config.MailTransportHTTP, ServiceURL: srv.URL, ClientID: "auth",
			Secret: secret, Timeout: time.Second, CAFile: caFile,
		})
		if err != nil {
			t.Fatalf("new remote: %v", err)
		}
		return m.SendCode(t.Context(), "u@example.com", auth.CodePurposeMFALogin, "1", time.Minute, "")
	}

	if err := send(""); err == nil {
		t.Fatal("certificate of an unknown CA accepted without MAIL_CA_FILE")
	}

	caFile := filepath.Join(t.TempDir(), "root.crt")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, block, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := send(caFile); err != nil {
		t.Fatalf("pinned CA rejected: %v", err)
	}
}

func TestRemoteRejectsBadCAFile(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "root.crt")
	os.WriteFile(bad, []byte("not a certificate"), 0o600)

	for _, path := range []string{bad, "/nonexistent/root.crt"} {
		_, err := mailer.NewRemote(config.MailConfig{
			Transport: config.MailTransportHTTP, ServiceURL: "https://mail.example.com",
			ClientID: "auth", Secret: secret, Timeout: time.Second, CAFile: path,
		})
		if err == nil {
			t.Errorf("%s: accepted", path)
		}
	}
}
