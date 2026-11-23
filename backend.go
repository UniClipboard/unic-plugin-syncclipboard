package syncclipboard

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/uniclipboard/unic/plugin"
)

const (
	ID          = "unic.syncclipboard"
	textMIME    = "text/plain"
	maxPart     = 2 << 20
	maxChannels = 32
	retention   = 30 * time.Minute
)

//go:embed settings.schema.json
var schema []byte

type Backend struct {
	receiver   plugin.Receiver
	authorizer plugin.ChannelAuthorizer
	listen     netip.AddrPort
	key        []byte
	server     *http.Server

	mu              sync.Mutex
	states          map[string]*channelState
	nextPublication uint64
	slots           chan struct{}
}

func (*Backend) Spec() plugin.Spec {
	return plugin.Spec{
		ID: ID, Version: "0.1.1", APIVersion: 1,
		Capabilities:  []string{plugin.CapSyncBackend},
		TransportKind: plugin.TransportObjectStore, ExternalChannels: true,
		SettingsSHA256: fmt.Sprintf("%x", sha256.Sum256(schema)),
	}
}

func (b *Backend) SetReceiver(r plugin.Receiver) {
	b.receiver = r
	b.authorizer, _ = r.(plugin.ChannelAuthorizer)
}

func (b *Backend) Init(_ context.Context, _ plugin.Host, cfg plugin.Config) error {
	key, _ := cfg["credential_key"].(string)
	raw, err := decodeKey(key)
	if err != nil {
		return plugin.ErrInvalidConfig
	}
	address := "127.0.0.1:42720"
	if value, ok := cfg["listen"]; ok {
		address, _ = value.(string)
	}
	listen, err := netip.ParseAddrPort(address)
	if err != nil || !listen.Addr().IsLoopback() || listen.Port() == 0 {
		return plugin.ErrInvalidConfig
	}
	b.listen, b.key = listen, raw
	b.states = make(map[string]*channelState)
	b.slots = make(chan struct{}, 4)
	return nil
}

func (b *Backend) Start(ctx context.Context) error {
	if b.authorizer == nil {
		return errors.New("plugin host does not provide channel authorization")
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", b.listen.String())
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /SyncClipboard.json", b.getDocument)
	mux.HandleFunc("PUT /SyncClipboard.json", b.putDocument)
	mux.HandleFunc("GET /file/{name}", b.getFile)
	mux.HandleFunc("PUT /file/{name}", b.putFile)
	b.server = &http.Server{
		Handler: b.authenticate(mux), ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second,
		IdleTimeout: 20 * time.Second, MaxHeaderBytes: 8192,
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go func() { _ = b.server.Serve(listener) }()
	return nil
}

func (b *Backend) Close(context.Context) error {
	if b.server == nil {
		return nil
	}
	return b.server.Close()
}

func (b *Backend) Submit(ctx context.Context, view plugin.SyncView, host plugin.SyncHost) (bool, error) {
	if len(view.Targets) == 0 {
		return false, nil
	}
	b.mu.Lock()
	b.nextPublication++
	sequence := b.nextPublication
	b.mu.Unlock()
	item, err := publicationFor(ctx, view)
	if err != nil {
		return false, err
	}
	if item == nil {
		return false, nil
	}
	if err := host.Register(view.Targets); err != nil {
		return false, err
	}
	now := time.Now()
	item.expires = now.Add(retention)
	item.sequence = sequence
	results := make([]plugin.SyncState, len(view.Targets))
	b.mu.Lock()
	b.prune(now)
	for i, id := range view.Targets {
		if ctx.Err() != nil {
			results[i] = plugin.SyncFailed
			continue
		}
		channel := b.state(id)
		if channel == nil {
			results[i] = plugin.SyncFailed
			continue
		}
		if channel.current != nil && channel.current.sequence > item.sequence {
			results[i] = plugin.SyncSuperseded
			continue
		}
		channel.previous, channel.current = channel.current, item
		results[i] = plugin.SyncSent
	}
	b.mu.Unlock()
	for i, id := range view.Targets {
		host.Report(id, results[i], nil)
	}
	return true, nil
}

type channelState struct {
	current, previous *publication
	upload            *upload
}

func (b *Backend) prune(now time.Time) {
	for id, channel := range b.states {
		if channel.upload != nil && !now.Before(channel.upload.expires) {
			channel.upload = nil
		}
		if channel.current != nil && !now.Before(channel.current.expires) {
			channel.current = nil
		}
		if channel.previous != nil && !now.Before(channel.previous.expires) {
			channel.previous = nil
		}
		if channel.current == nil && channel.previous == nil && channel.upload == nil {
			delete(b.states, id)
		}
	}
}

// state must be called with mu held, after pruning expired records.
func (b *Backend) state(id string) *channelState {
	if s := b.states[id]; s != nil {
		return s
	}
	if len(b.states) >= maxChannels {
		return nil
	}
	s := &channelState{}
	b.states[id] = s
	return s
}

func decodeKey(key string) ([]byte, error) {
	data, err := hex.DecodeString(key)
	if err != nil || len(data) != 32 {
		return nil, errors.New("credential key must contain 32 hexadecimal bytes")
	}
	return data, nil
}

func validUser(id string) bool {
	return len(id) > 0 && len(id) <= 128 && strings.IndexFunc(id, func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_')
	}) < 0
}

func credential(key []byte, id string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, "unic.syncclipboard credential v1\x00"+id)
	return hex.EncodeToString(mac.Sum(nil))
}

func Password(key, id string) (string, error) {
	raw, err := decodeKey(key)
	if err != nil {
		return "", err
	}
	if !validUser(id) {
		return "", errors.New("invalid channel ID")
	}
	return credential(raw, id), nil
}

func validName(name string) bool {
	return name != "" && len(name) <= 200 && utf8.ValidString(name) && name != "." && name != ".." &&
		!strings.ContainsAny(name, "/\\:") && strings.IndexFunc(name, func(r rune) bool { return r < 32 || r == 127 }) < 0
}
