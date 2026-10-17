package mailer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Sign — подпись запроса к mail-service (HMAC-SHA256 по строке
// "v1\n<timestamp>\n<METHOD>\n<path>\n<hex(sha256(body))>"). Формат должен
// совпадать с mail-service/internal/middleware/apikey.Sign: оба репозитория
// проверяют один и тот же golden-вектор, расхождение ловится тестом.
func Sign(secret []byte, timestamp, method, path string, body []byte) []byte {
	bodyHash := sha256.Sum256(body)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strings.Join([]string{
		"v1", timestamp, method, path, hex.EncodeToString(bodyHash[:]),
	}, "\n")))
	return mac.Sum(nil)
}
