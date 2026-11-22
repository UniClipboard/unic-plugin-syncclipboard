package syncclipboard

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/uniclipboard/unic/plugin"
)

type document struct {
	Type             string     `json:"type"`
	Text             string     `json:"text"`
	HasData          bool       `json:"hasData"`
	DataName         string     `json:"dataName,omitempty"`
	Hash             string     `json:"hash,omitempty"`
	TransferDataHash string     `json:"transferDataHash,omitempty"`
	Size             int        `json:"size"`
	SyncedAt         *time.Time `json:"syncedAt,omitempty"`
}

type publication struct {
	doc      document
	mime     string
	body     []byte
	sequence uint64
	expires  time.Time
}

type upload struct {
	name    string
	body    []byte
	expires time.Time
}

func checksum(data []byte) string {
	return fmt.Sprintf("%X", sha256.Sum256(data))
}

func imageExtension(mime string) string {
	switch mime {
	case "image/png":
		return ".png"
	case "image/jpeg":
		return ".jpg"
	case "image/gif":
		return ".gif"
	case "image/webp":
		return ".webp"
	}
	return ""
}

func publicationFor(ctx context.Context, view plugin.SyncView) (*publication, error) {
	var selected *plugin.SyncPart
	for i := range view.Parts {
		part := &view.Parts[i]
		if part.File || part.Size <= 0 || part.Size > maxPart {
			continue
		}
		if imageExtension(part.MIME) != "" {
			selected = part
			break
		}
		if selected == nil && part.MIME == textMIME {
			selected = part
		}
	}
	if selected == nil {
		return nil, nil
	}
	r, err := selected.Open(ctx)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	content, err := io.ReadAll(io.LimitReader(r, selected.Size+1))
	if err != nil || int64(len(content)) != selected.Size {
		return nil, errors.New("could not read the complete representation")
	}
	syncedAt := time.Now().UTC()
	out := &publication{mime: selected.MIME}
	out.doc = document{Size: len(content), SyncedAt: &syncedAt}
	if selected.MIME == textMIME {
		if !utf8.Valid(content) {
			return nil, errors.New("text is not UTF-8")
		}
		out.doc.Type = "Text"
		out.doc.Text = string(content)
		out.doc.Hash = checksum(content)
		return out, nil
	}
	if http.DetectContentType(content) != selected.MIME {
		return nil, errors.New("image representation differs from its media type")
	}
	out.body = content
	out.doc.Type = "Image"
	out.doc.HasData = true
	out.doc.DataName = strings.ToLower(checksum([]byte(view.ID))) + imageExtension(selected.MIME)
	out.doc.Text = out.doc.DataName
	out.doc.TransferDataHash = checksum(content)
	out.doc.Hash = checksum([]byte(out.doc.DataName + "|" + out.doc.TransferDataHash))
	return out, nil
}
