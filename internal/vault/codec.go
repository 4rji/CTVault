package vault

import (
	"fmt"

	"github.com/klauspost/compress/zstd"
)

// maxCert bounds a decompressed certificate: RFC 6962 encodes certificates
// with 24-bit lengths.
const maxCert = 1 << 24

// Codec compresses and decompresses record frames. Frames carry a content
// checksum. A frame's own dictionary ID must equal the record's dict_id, so
// a record can never be decoded with the wrong dictionary. Leaf and chain
// frames are libzstd level 9 (amendment A2 §2.1); delta frames are
// klauspost's default level, as small for deltas and 3.5x faster than its
// better level (measured 2026-10-04). Delta frames use their base
// certificate as a raw dictionary with ID 0, so the frame's dictionary ID
// is omitted (spec §6.2). Every frame is read with klauspost's decoders,
// whichever encoder wrote it. A Codec is not safe for concurrent use.
type Codec struct {
	enc      map[uint64]*cEncoder // dict_id → encoder
	dicts    map[uint64][]byte    // trained dictionaries by ID
	dec      *zstd.Decoder        // leaf and chain frames
	deltaEnc *zstd.Encoder        // reset with each base
	deltaDec *zstd.Decoder        // reset with each base
}

func newDecoder(dicts map[uint64][]byte) (*zstd.Decoder, error) {
	opts := []zstd.DOption{zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxCert)}
	var ds [][]byte
	for _, d := range dicts {
		ds = append(ds, d)
	}
	if len(ds) > 0 {
		opts = append(opts, zstd.WithDecoderDicts(ds...))
	}
	return zstd.NewReader(nil, opts...)
}

// NewCodec returns a codec that knows dict_id 0 (no dictionary).
func NewCodec() (*Codec, error) {
	enc, err := newCEncoder(nil)
	if err != nil {
		return nil, err
	}
	dec, err := newDecoder(nil)
	if err != nil {
		return nil, err
	}
	deltaEnc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderCRC(true),
		zstd.WithEncoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	deltaDec, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxCert))
	if err != nil {
		return nil, err
	}
	return &Codec{enc: map[uint64]*cEncoder{0: enc}, dicts: map[uint64][]byte{}, dec: dec,
		deltaEnc: deltaEnc, deltaDec: deltaDec}, nil
}

// AddDict registers trained dictionary id (a zstd dictionary whose own ID
// is id) for compression and decompression.
func (c *Codec) AddDict(id uint64, content []byte) error {
	if id == 0 {
		return fmt.Errorf("vault: dictionary ID 0 means no dictionary")
	}
	enc, err := newCEncoder(content)
	if err != nil {
		return fmt.Errorf("vault: dictionary %d: %w", id, err)
	}
	dicts := map[uint64][]byte{id: content}
	for k, v := range c.dicts {
		dicts[k] = v
	}
	dec, err := newDecoder(dicts)
	if err != nil {
		enc.close()
		return fmt.Errorf("vault: dictionary %d: %w", id, err)
	}
	c.dec.Close()
	if old, ok := c.enc[id]; ok {
		old.close()
	}
	c.dec, c.dicts, c.enc[id] = dec, dicts, enc
	return nil
}

// CompressDelta encodes der against base (spec §6.2 leaf-delta).
func (c *Codec) CompressDelta(der, base []byte) ([]byte, error) {
	if err := c.deltaEnc.ResetWithOptions(nil, zstd.WithEncoderDictRaw(0, base)); err != nil {
		return nil, err
	}
	return c.deltaEnc.EncodeAll(der, nil), nil
}

// DecompressDelta decodes a delta frame against its base.
func (c *Codec) DecompressDelta(frame, base []byte) ([]byte, error) {
	var h zstd.Header
	if err := h.Decode(frame); err != nil {
		return nil, corrupt("delta frame header: %v", err)
	}
	if h.DictionaryID != 0 {
		return nil, corrupt("delta frame names dictionary %d", h.DictionaryID)
	}
	if err := c.deltaDec.ResetWithOptions(nil, zstd.WithDecoderDictRaw(0, base)); err != nil {
		return nil, err
	}
	der, err := c.deltaDec.DecodeAll(frame, nil)
	if err != nil {
		return nil, corrupt("decompressing delta: %v", err)
	}
	return der, nil
}

// Compress encodes der with dictionary dictID.
func (c *Codec) Compress(der []byte, dictID uint64) ([]byte, error) {
	e, ok := c.enc[dictID]
	if !ok {
		return nil, fmt.Errorf("vault: no dictionary %d", dictID)
	}
	return e.encode(der)
}

// Decompress decodes a leaf or chain frame written with dictID.
func (c *Codec) Decompress(frame []byte, dictID uint64) ([]byte, error) {
	var h zstd.Header
	if err := h.Decode(frame); err != nil {
		return nil, corrupt("frame header: %v", err)
	}
	if uint64(h.DictionaryID) != dictID {
		return nil, corrupt("frame uses dictionary %d, record says %d", h.DictionaryID, dictID)
	}
	der, err := c.dec.DecodeAll(frame, nil)
	if err != nil {
		return nil, corrupt("decompressing: %v", err)
	}
	return der, nil
}

// Close releases the codec's encoders and decoders.
func (c *Codec) Close() {
	for _, e := range c.enc {
		e.close()
	}
	c.dec.Close()
	c.deltaEnc.Close()
	c.deltaDec.Close()
}
