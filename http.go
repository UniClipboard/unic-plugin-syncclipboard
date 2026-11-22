package syncclipboard

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/uniclipboard/unic/plugin"
)

func (b *Backend) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		id, password, ok := r.BasicAuth()
		if !ok || !validUser(id) || !hmac.Equal([]byte(password), []byte(credential(b.key, id))) {
			w.Header().Set("WWW-Authenticate", `Basic realm="SyncClipboard"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		select {
		case b.slots <- struct{}{}:
			defer func() { <-b.slots }()
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if b.authorize(w, r, id, "") {
			next.ServeHTTP(w, r)
		}
	})
}

func (b *Backend) authorize(w http.ResponseWriter, r *http.Request, id, mime string) bool {
	allowed, err := b.authorizer.AuthorizeChannel(r.Context(), id, mime)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return false
	}
	if !allowed {
		w.WriteHeader(http.StatusForbidden)
	}
	return allowed
}

func (b *Backend) getDocument(w http.ResponseWriter, r *http.Request) {
	id, _, _ := r.BasicAuth()
	doc := document{Type: "Text"}
	mime := textMIME
	b.mu.Lock()
	b.prune(time.Now())
	if channel := b.states[id]; channel != nil && channel.current != nil {
		doc, mime = channel.current.doc, channel.current.mime
	}
	b.mu.Unlock()
	if !b.authorize(w, r, id, mime) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (b *Backend) getFile(w http.ResponseWriter, r *http.Request) {
	id, _, _ := r.BasicAuth()
	name := r.PathValue("name")
	var item *publication
	b.mu.Lock()
	b.prune(time.Now())
	if channel := b.states[id]; channel != nil {
		for _, candidate := range []*publication{channel.current, channel.previous} {
			if candidate != nil && candidate.doc.HasData && candidate.doc.DataName == name {
				item = candidate
				break
			}
		}
	}
	b.mu.Unlock()
	if item == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if b.authorize(w, r, id, item.mime) {
		w.Header().Set("Content-Type", item.mime)
		_, _ = w.Write(item.body)
	}
}

func (b *Backend) putFile(w http.ResponseWriter, r *http.Request) {
	id, _, _ := r.BasicAuth()
	name := r.PathValue("name")
	if !validName(name) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	data, ok := readBody(w, r, maxPart)
	if !ok {
		return
	}
	mime := http.DetectContentType(data)
	if imageExtension(mime) == "" {
		if !strings.HasSuffix(strings.ToLower(name), ".txt") || !utf8.Valid(data) {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		mime = textMIME
	}
	if !b.authorize(w, r, id, mime) {
		return
	}
	now := time.Now()
	b.mu.Lock()
	b.prune(now)
	channel := b.state(id)
	if channel != nil {
		channel.upload = &upload{name: name, body: data, expires: now.Add(time.Minute)}
	}
	b.mu.Unlock()
	if channel == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (b *Backend) putDocument(w http.ResponseWriter, r *http.Request) {
	id, _, _ := r.BasicAuth()
	raw, ok := readBody(w, r, 6*maxPart+4096)
	if !ok {
		return
	}
	var in struct {
		document
		Text    *string `json:"text"`
		HasData *bool   `json:"hasData"`
	}
	if !utf8.Valid(raw) || json.Unmarshal(raw, &in) != nil || in.Text == nil || in.HasData == nil || in.Type == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if in.Type != "Text" && in.Type != "Image" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	data := []byte(*in.Text)
	mime := textMIME
	hash := ""
	if *in.HasData {
		if !validName(in.DataName) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		b.mu.Lock()
		b.prune(time.Now())
		var staged *upload
		if channel := b.states[id]; channel != nil && channel.upload != nil && channel.upload.name == in.DataName {
			staged, channel.upload = channel.upload, nil
		}
		b.mu.Unlock()
		if staged == nil {
			w.WriteHeader(http.StatusConflict)
			return
		}
		data = staged.body
		dataHash := checksum(data)
		if in.TransferDataHash != "" && !strings.EqualFold(in.TransferDataHash, dataHash) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if in.Type == "Image" {
			mime = http.DetectContentType(data)
			if imageExtension(mime) == "" {
				w.WriteHeader(http.StatusUnsupportedMediaType)
				return
			}
			hash = checksum([]byte(in.DataName + "|" + dataHash))
		}
	} else if in.Type == "Image" || in.DataName != "" || in.TransferDataHash != "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if hash == "" {
		hash = checksum(data)
	}
	if len(data) == 0 || len(data) > maxPart || (mime == textMIME && !utf8.Valid(data)) ||
		(in.Hash != "" && !strings.EqualFold(in.Hash, hash)) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !b.authorize(w, r, id, mime) {
		return
	}
	b.mu.Lock()
	b.prune(time.Now())
	channel := b.states[id]
	echo := channel != nil && channel.current != nil && strings.EqualFold(channel.current.doc.Hash, hash)
	b.mu.Unlock()
	if !echo {
		err := b.receiver.Receive(r.Context(), id, plugin.Received{
			Transfer: rand.Text(), View: hash, Parts: []plugin.ReceivedPart{{MIME: mime, Data: data}},
		})
		if err != nil {
			w.WriteHeader(http.StatusConflict)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	buf, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
		return nil, false
	}
	return buf, true
}
