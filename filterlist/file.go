package filterlist

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/c2h5oh/datasize"
)

// FileConfig represents configuration for a file-based rule list.
type FileConfig struct {
	// Path is the path to the file with rules.
	Path string

	// ID is the rule list identifier.
	ID rules.ListID

	// IgnoreCosmetic tells whether to ignore cosmetic rules or not.
	IgnoreCosmetic bool
}

// File is an [Interface] implementation which stores rules within a file.
type File struct {
	// mu protects all the fields.
	//
	// TODO(a.garipov):  This mutex is not sufficient; File and scanners should
	// be reimplemented with [io.ReaderAt] in mind.
	mu *sync.Mutex

	// file is the file with rules.
	file *os.File

	// builder used to construct strings.
	builder *strings.Builder

	// buffer used for reading from the file.
	buffer []byte

	// id is the rule list ID.
	id rules.ListID

	// ignoreCosmetic tells whether to ignore cosmetic rules or not.
	ignoreCosmetic bool

	// size is the initial size of the file used as the estimate of its
	// contents' overall size.
	size datasize.ByteSize
}

// NewFile creates a new file-based rule list with the given configuration.
func NewFile(conf *FileConfig) (f *File, err error) {
	f = &File{
		mu:             &sync.Mutex{},
		id:             conf.ID,
		builder:        &strings.Builder{},
		buffer:         make([]byte, readerBufferSize),
		ignoreCosmetic: conf.IgnoreCosmetic,
	}

	f.file, err = os.Open(filepath.Clean(conf.Path))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.WithDeferred(err, f.file.Close())
		}
	}()

	fi, err := f.file.Stat()
	if err != nil {
		return nil, fmt.Errorf("getting fileinfo for size estimation: %w", err)
	}

	// #nosec G115 -- Files cannot have negative sizes.
	f.size = datasize.ByteSize(fi.Size())

	return f, nil
}

// type check
var _ Interface = (*File)(nil)

// Close closes the underlying file.
func (f *File) Close() (err error) {
	return f.file.Close()
}

// ListID returns the rule list identifier.
func (f *File) ListID() (id rules.ListID) {
	return f.id
}

// NewScanner creates a new rules scanner that reads the list contents.
func (f *File) NewScanner() (sc *RuleScanner) {
	_, _ = f.file.Seek(0, io.SeekStart)

	return NewRuleScanner(f.file, f.id, f.ignoreCosmetic)
}

// RetrieveRule finds and deserializes rule by its index.  If there's no rule by
// that index or rule is invalid, it will return an error.
func (f *File) RetrieveRule(ruleIdx int64) (r rules.Rule, err error) {
	errors.Check(validate.NotNegative("ruleIdx", ruleIdx))

	f.mu.Lock()
	defer f.mu.Unlock()

	_, err = f.file.Seek(ruleIdx, io.SeekStart)
	if err != nil {
		return nil, err
	}

	// Read line from the file.
	line, err := f.readLine()
	if err == io.EOF {
		err = nil
	}

	// Check if there were any errors while reading.
	if err != nil {
		return nil, err
	}

	line = strings.TrimSpace(line)
	if len(line) == 0 {
		return nil, ErrRuleRetrieval
	}

	return rules.NewRule(line, f.id)
}

// SizeEstimate implements the [Interface] interface for *File.
func (f *File) SizeEstimate() (est datasize.ByteSize) {
	return f.size
}

// readLine reads from the reader until '\n'.  r is the reader to read from.  b
// is the buffer to use (the idea is to reuse the same buffer when it's
// possible).
//
// TODO(a.garipov):  Consider ways of using [bufio.Reader] here.
func (f *File) readLine() (line string, err error) {
	f.builder.Reset()

	var n int
	for {
		n, err = f.file.Read(f.buffer)
		if n == 0 {
			return f.builder.String(), err
		}

		idx := bytes.IndexByte(f.buffer[:n], '\n')
		if idx == -1 {
			_, _ = f.builder.Write(f.buffer[:n])

			continue
		}

		_, _ = f.builder.Write(f.buffer[:idx])

		return f.builder.String(), nil
	}
}
