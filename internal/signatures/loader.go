package signatures

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Loader manages loading Suricata rules from disk with hot-reload support.
type Loader struct {
	mu       sync.RWMutex
	rules    []*Rule
	rulesBySID map[int]*Rule
	dirs     []string
	lastLoad time.Time

	// Stats
	totalLoaded  uint64
	totalErrors  uint64
	totalMatches uint64

	// Hot-reload
	reloadInterval time.Duration
	done           chan struct{}
	wg             sync.WaitGroup
}

// NewLoader creates a rule loader for the given directories.
func NewLoader(dirs []string) *Loader {
	return &Loader{
		dirs:           dirs,
		rulesBySID:     make(map[int]*Rule),
		reloadInterval: 10 * time.Second,
		done:           make(chan struct{}),
	}
}

// Load reads all .rules files from configured directories and parses them.
// Returns the number of rules loaded and any parse errors.
func (l *Loader) Load() (int, []error) {
	var allRules []*Rule
	var allErrors []error

	for _, dir := range l.dirs {
		rules, errs := loadDir(dir)
		allRules = append(allRules, rules...)
		allErrors = append(allErrors, errs...)
	}

	// Atomic swap — build new index, then swap under lock.
	newIndex := make(map[int]*Rule, len(allRules))
	for _, r := range allRules {
		newIndex[r.SID] = r
	}

	l.mu.Lock()
	l.rules = allRules
	l.rulesBySID = newIndex
	l.lastLoad = time.Now()
	l.mu.Unlock()

	atomic.StoreUint64(&l.totalLoaded, uint64(len(allRules)))
	atomic.StoreUint64(&l.totalErrors, uint64(len(allErrors)))

	return len(allRules), allErrors
}

// Rules returns a snapshot of the currently loaded rules.
func (l *Loader) Rules() []*Rule {
	l.mu.RLock()
	defer l.mu.RUnlock()
	// Return a copy of the slice header (rules themselves are not copied).
	rules := make([]*Rule, len(l.rules))
	copy(rules, l.rules)
	return rules
}

// GetRule returns a rule by SID.
func (l *Loader) GetRule(sid int) (*Rule, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	r, ok := l.rulesBySID[sid]
	return r, ok
}

// RuleCount returns the number of loaded rules.
func (l *Loader) RuleCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.rules)
}

// Stats returns loader statistics.
func (l *Loader) Stats() (loaded, errors, matches uint64) {
	return atomic.LoadUint64(&l.totalLoaded),
		atomic.LoadUint64(&l.totalErrors),
		atomic.LoadUint64(&l.totalMatches)
}

// IncrementMatches increments the match counter.
func (l *Loader) IncrementMatches() {
	atomic.AddUint64(&l.totalMatches, 1)
}

// StartHotReload begins periodic reload of rules from disk.
func (l *Loader) StartHotReload() {
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		ticker := time.NewTicker(l.reloadInterval)
		defer ticker.Stop()

		for {
			select {
			case <-l.done:
				return
			case <-ticker.C:
				l.reload()
			}
		}
	}()
	log.Printf("[signatures] Hot-reload enabled (interval=%s)", l.reloadInterval)
}

// Stop shuts down the hot-reload goroutine.
func (l *Loader) Stop() {
	close(l.done)
	l.wg.Wait()
}

// Reload forces an immediate reload of rules.
func (l *Loader) Reload() (int, []error) {
	return l.Load()
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

func (l *Loader) reload() {
	l.mu.RLock()
	lastLoad := l.lastLoad
	l.mu.RUnlock()

	// Check if any rule files have been modified since last load.
	modified := false
	for _, dir := range l.dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".rules") {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if info.ModTime().After(lastLoad) {
				modified = true
				break
			}
		}
		if modified {
			break
		}
	}

	if !modified {
		return
	}

	count, errs := l.Load()
	if len(errs) > 0 {
		log.Printf("[signatures] Hot-reload: %d rules loaded, %d errors", count, len(errs))
	} else {
		log.Printf("[signatures] Hot-reload: %d rules loaded", count)
	}
}

func loadDir(dir string) ([]*Rule, []error) {
	var allRules []*Rule
	var allErrors []error

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []error{fmt.Errorf("read dir %s: %w", dir, err)}
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rules") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			allErrors = append(allErrors, fmt.Errorf("read %s: %w", path, err))
			continue
		}

		rules, errs := ParseRules(string(data))
		allRules = append(allRules, rules...)
		for _, e := range errs {
			allErrors = append(allErrors, fmt.Errorf("%s: %w", entry.Name(), e))
		}
	}

	return allRules, allErrors
}
