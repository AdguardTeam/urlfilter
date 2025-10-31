package filterlist

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/syncutil"
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
	// file is the file with rules.
	file *os.File

	// bytesPool reuses byte buffers for copying responses.
	bytesPool *syncutil.Pool[[]byte]

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
		id:             conf.ID,
		bytesPool:      syncutil.NewSlicePool[byte](int(readerBufferSize)),
		ignoreCosmetic: conf.IgnoreCosmetic,
	}

	f.file, err = os.Open(filepath.Clean(conf.Path))
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
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

// NewScanner creates a new rules scanner that reads the list contents.  The
// returned scanner should not be used concurrently with RetrieveRule.
func (f *File) NewScanner() (sc *RuleScanner) {
	_, _ = f.file.Seek(0, io.SeekStart)

	return NewRuleScanner(f.file, f.id, f.ignoreCosmetic)
}

// RetrieveRule finds and deserializes rule by its index.  If there's no rule by
// that index or rule is invalid, it will return an error.  It should not be
// used concurrently with the scanner returned from NewScanner.
func (f *File) RetrieveRule(ruleIdx int64) (r rules.Rule, err error) {
	errors.Check(validate.NotNegative("ruleIdx", ruleIdx))

	// Read line from the file.
	line, err := f.readLine(ruleIdx)
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

// readLine reads from the reader with the given offset until '\n'.  r is the
// reader to read from.  b is the buffer to use (the idea is to reuse the same
// buffer when it's possible).
//
// TODO(a.garipov):  Consider ways of using [bufio.Reader] here.
func (f *File) readLine(offset int64) (line string, err error) {
	bufPtr := f.bytesPool.Get()
	defer f.bytesPool.Put(bufPtr)

	var n int
	var read int
	for {
		n, err = f.file.ReadAt((*bufPtr)[read:], offset+int64(n))
		if n == 0 {
			return string(*bufPtr), err
		}

		idx := bytes.IndexByte((*bufPtr)[read:read+n], '\n')
		if idx == -1 {
			read += n

			continue
		}

		return string((*bufPtr)[:read+idx]), nil
	}
}
