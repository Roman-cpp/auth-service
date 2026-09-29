package qrlogin

import "sync"

// hub будит наблюдателей заявки, когда её статус меняется на этом же
// экземпляре сервиса. Это только ускорение: изменения с других экземпляров
// наблюдатель всё равно увидит по таймеру (см. pollInterval).
type hub struct {
	mu   sync.Mutex
	subs map[string]map[chan struct{}]struct{}
}

func newHub() *hub {
	return &hub{subs: map[string]map[chan struct{}]struct{}{}}
}

func (h *hub) subscribe(id string) (<-chan struct{}, func()) {
	// Буфер в одно место: пропущенные между проверками пинки схлопываются,
	// наблюдателю всё равно перечитывать заявку целиком.
	ch := make(chan struct{}, 1)

	h.mu.Lock()
	if h.subs[id] == nil {
		h.subs[id] = map[chan struct{}]struct{}{}
	}
	h.subs[id][ch] = struct{}{}
	h.mu.Unlock()

	return ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		delete(h.subs[id], ch)
		if len(h.subs[id]) == 0 {
			delete(h.subs, id)
		}
	}
}

func (h *hub) notify(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[id] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
