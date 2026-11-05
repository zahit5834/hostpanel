package jobs

import "sync"

// Event types sent to subscribers.
const (
	EventLine     = "line"
	EventProgress = "progress"
	EventStatus   = "status"
)

// Event is one message on a job's live stream.
type Event struct {
	Seq  int64 // line sequence number (EventLine only)
	Type string
	Data string
}

// subBuffer is per-subscriber backlog. A subscriber that falls this far behind
// is dropped (its channel closed) instead of blocking the job; the browser's
// EventSource reconnects and replays from the log file.
const subBuffer = 256

// Broker fans out job events to SSE subscribers. It holds no goroutines.
type Broker struct {
	mu   sync.Mutex
	subs map[int64]map[chan Event]struct{}
}

// NewBroker creates an empty broker.
func NewBroker() *Broker { return &Broker{subs: make(map[int64]map[chan Event]struct{})} }

// Subscribe returns a channel of events for job id and an unsubscribe func.
// The channel is closed when the job ends, the subscriber is too slow, or
// unsubscribe is called. Calling unsubscribe more than once is safe.
func (b *Broker) Subscribe(id int64) (<-chan Event, func()) {
	ch := make(chan Event, subBuffer)
	b.mu.Lock()
	if b.subs[id] == nil {
		b.subs[id] = make(map[chan Event]struct{})
	}
	b.subs[id][ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() { b.remove(id, ch) }
}

func (b *Broker) remove(id int64, ch chan Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if set, ok := b.subs[id]; ok {
		if _, ok := set[ch]; ok {
			delete(set, ch)
			close(ch)
		}
		if len(set) == 0 {
			delete(b.subs, id)
		}
	}
}

// Publish delivers ev to every subscriber of id without ever blocking.
func (b *Broker) Publish(id int64, ev Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs[id] {
		select {
		case ch <- ev:
		default:
			delete(b.subs[id], ch)
			close(ch)
		}
	}
}

// CloseTopic ends all streams for id.
func (b *Broker) CloseTopic(id int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs[id] {
		close(ch)
	}
	delete(b.subs, id)
}

// Subscribers returns the current subscriber count (for tests and diagnostics).
func (b *Broker) Subscribers(id int64) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs[id])
}
