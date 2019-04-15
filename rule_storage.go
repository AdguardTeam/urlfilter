package urlfilter

import (
	"bufio"
	"errors"
	"io"
	"log"
	"os"
	"sync"
)

// RulesStorage uses rules serialization/deserialization to store them in a single byte array or file.
// The idea is to store rules in a minimized serialized form and deserialize them on-demand only.
// This will allow us to minimize amount of RAM used by the filtering engine.
// Please note that we keep all retrieved rules in memory because we consider that only a tiny part
// of all loaded rules will be used.
// TODO: Consider using LRU cache instead of map
type RulesStorage struct {
	buffer         io.ReadWriteSeeker // buffer with serialized rules
	bufferedWriter *bufio.Writer      // buffered writer is used to speed up writing to a file
	currentIndex   int64              // current index in the buffer
	bufferLength   int64              // bufferLength

	cache map[int64]Rule // cache with the rules which were retrieved

	sync.Mutex
}

// NewRuleStorage creates a new rules storage
// If filePath is not empty, we will create a temporary file on the disk and store
// serialized rules there. Otherwise, we will store everything in memory.
func NewRuleStorage(filePath string) (*RulesStorage, error) {
	var buffer io.ReadWriteSeeker

	if filePath != "" {
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		buffer = file
	} else {
		buffer = newMemFile()
	}

	s := &RulesStorage{
		buffer:         buffer,
		bufferedWriter: bufio.NewWriter(buffer),
		cache:          map[int64]Rule{},
	}

	return s, nil
}

// Close closes the rule storage and frees underlying resources
// This is important in the case of a file-based storage:
// The file will be closed and deleted.
func (s *RulesStorage) Close() error {
	s.Lock()
	defer s.Unlock()

	file, ok := s.buffer.(*os.File)
	if !ok {
		// In-memory storage -- doing nothing
		return nil
	}

	err := file.Close()
	if err != nil {
		return err
	}
	return os.Remove(file.Name())
}

// Store saves rule to the rule storage and returns the index of the rule
func (s *RulesStorage) Store(rule Rule) (int64, error) {
	s.Lock()
	defer s.Unlock()

	var ruleIndex int64

	if s.currentIndex == s.bufferLength {
		ruleIndex = s.currentIndex
	} else {
		idx, err := s.buffer.Seek(0, io.SeekEnd)
		if err != nil {
			return 0, err
		}
		ruleIndex = idx
	}

	count, err := SerializeRule(rule, s.bufferedWriter)
	s.bufferLength += int64(count)
	s.currentIndex = s.bufferLength
	if err != nil {
		return 0, err
	}

	return ruleIndex, nil
}

// Retrieve gets the rule from the storage by its index
func (s *RulesStorage) Retrieve(idx int64) (Rule, error) {
	s.Lock()
	defer s.Unlock()

	rule, ok := s.cache[idx]
	if ok {
		return rule, nil
	}

	// Make sure that we've written everything to the file
	err := s.bufferedWriter.Flush()
	if err != nil {
		return nil, err
	}

	_, err = s.buffer.Seek(idx, io.SeekStart)
	if err != nil {
		return nil, err
	}

	rule, err = DeserializeRule(s.buffer)
	if err != nil {
		return nil, err
	}

	s.cache[idx] = rule
	return rule, nil
}

// RetrieveNetworkRule is a helper method that retrieves a network rule from the storage
// It returns a pointer to the rule or nil in any other case (not found or error)
func (s *RulesStorage) RetrieveNetworkRule(idx int64) *NetworkRule {
	r, err := s.Retrieve(idx)
	if err != nil {
		log.Printf("Cannot retrieve rule %d: %s", idx, err)
		return nil
	}

	v, ok := r.(*NetworkRule)
	if ok {
		return v
	}

	return nil
}

// RetrieveHostRule is a helper method that retrieves a host rule from the storage
// It returns a pointer to the rule or nil in any other case (not found or error)
func (s *RulesStorage) RetrieveHostRule(idx int64) *HostRule {
	r, err := s.Retrieve(idx)
	if err != nil {
		log.Printf("Cannot retrieve rule %d: %s", idx, err)
		return nil
	}

	v, ok := r.(*HostRule)
	if ok {
		return v
	}

	return nil
}

var errInvalidArgument = errors.New("invalid argument")

// Simple io.ReadWriteSeeker implementation
type memFile struct {
	b      []byte
	index  int64
	length int64

	sync.Mutex
}

// newMemFile initializes a new instance of memFile
func newMemFile() *memFile {
	return &memFile{
		b: make([]byte, 16*1024),
	}
}

// Read reads up to len(b) bytes from the File.
// It returns the number of bytes read and any error encountered.
// At end of file, Read returns (0, io.EOF).
func (f *memFile) Read(b []byte) (int, error) {
	f.Lock()
	defer f.Unlock()

	n, err := f.readAt(b, f.index)
	f.index += int64(n)
	return n, err
}

// Write writes len(b) bytes to the File.
// It returns the number of bytes written and an error, if any.
// If the current file offset is past the io.EOF, then the space in-between are
// implicitly filled with zero bytes.
func (f *memFile) Write(b []byte) (int, error) {
	f.Lock()
	defer f.Unlock()

	n, err := f.writeAt(b, f.index)
	f.index += int64(n)
	f.length += int64(n)
	return n, err
}

// Seek sets the offset for the next Read or Write on file with offset,
// interpreted according to whence: 0 means relative to the origin of the file,
// 1 means relative to the current offset, and 2 means relative to the end.
func (f *memFile) Seek(offset int64, whence int) (int64, error) {
	f.Lock()
	defer f.Unlock()

	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = f.index + offset
	case io.SeekEnd:
		abs = f.length + offset
	default:
		return 0, errInvalidArgument
	}
	if abs < 0 {
		return 0, errInvalidArgument
	}
	f.index = abs
	return abs, nil
}

func (f *memFile) readAt(b []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errInvalidArgument
	}
	if off > f.length {
		return 0, io.EOF
	}
	n := copy(b, f.b[off:])
	if n < len(b) {
		return n, io.EOF
	}
	return n, nil
}

func (f *memFile) writeAt(b []byte, off int64) (int, error) {
	if off < 0 || off > f.length {
		return 0, errInvalidArgument
	}

	count := off + int64(len(b))
	for count > int64(len(f.b)) {
		n := make([]byte, len(f.b)*2)
		copy(n, f.b)
		f.b = n
		count = off + int64(len(b))
	}

	copy(f.b[off:], b)
	return len(b), nil
}
