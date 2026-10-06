package vault

// libzstd, compiled from source by github.com/DataDog/zstd (amendment A2
// §2.1), reached through its stable public C API. CTVault declares the few
// functions it calls instead of including zstd.h, whose path is the
// dependency's module directory.

/*
#include <stddef.h>

typedef struct ZSTD_CCtx_s ZSTD_CCtx;
typedef struct ZSTD_CDict_s ZSTD_CDict;
ZSTD_CCtx* ZSTD_createCCtx(void);
size_t ZSTD_freeCCtx(ZSTD_CCtx* cctx);
size_t ZSTD_CCtx_setParameter(ZSTD_CCtx* cctx, int param, int value);
ZSTD_CDict* ZSTD_createCDict(const void* dictBuffer, size_t dictSize, int compressionLevel);
size_t ZSTD_freeCDict(ZSTD_CDict* cdict);
size_t ZSTD_CCtx_refCDict(ZSTD_CCtx* cctx, const ZSTD_CDict* cdict);
size_t ZSTD_compress2(ZSTD_CCtx* cctx, void* dst, size_t dstCapacity, const void* src, size_t srcSize);
size_t ZSTD_compressBound(size_t srcSize);
unsigned ZSTD_isError(size_t code);
const char* ZSTD_getErrorName(size_t code);
const char* ZSTD_versionString(void);

size_t ZDICT_trainFromBuffer(void* dictBuffer, size_t dictBufferCapacity,
	const void* samplesBuffer, const size_t* samplesSizes, unsigned nbSamples);
unsigned ZDICT_isError(size_t code);
const char* ZDICT_getErrorName(size_t code);
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"

	_ "github.com/DataDog/zstd" // compiles libzstd 1.5.7, zdict.c included
)

// Full records are compressed at this level (amendment A2 §2.1).
const cLevel = 9

// ZSTD_cParameter values from zstd.h (stable API).
const (
	zstdCCompressionLevel = 100
	zstdCChecksumFlag     = 201
)

// ZstdVersion is the libzstd version compiled into this binary.
func ZstdVersion() string { return C.GoString(C.ZSTD_versionString()) }

// cEncoder compresses full records with libzstd at level 9, with a content
// checksum and, when it has a dictionary, the dictionary's ID in each frame.
// It is not safe for concurrent use.
type cEncoder struct {
	cctx  *C.ZSTD_CCtx
	cdict *C.ZSTD_CDict
}

func zstdErr(code C.size_t) error {
	if C.ZSTD_isError(code) != 0 {
		return errors.New(C.GoString(C.ZSTD_getErrorName(code)))
	}
	return nil
}

func newCEncoder(dict []byte) (*cEncoder, error) {
	e := &cEncoder{cctx: C.ZSTD_createCCtx()}
	if e.cctx == nil {
		return nil, errors.New("vault: libzstd could not allocate a compression context")
	}
	for _, p := range [][2]C.int{{zstdCCompressionLevel, cLevel}, {zstdCChecksumFlag, 1}} {
		if err := zstdErr(C.ZSTD_CCtx_setParameter(e.cctx, p[0], p[1])); err != nil {
			e.close()
			return nil, fmt.Errorf("vault: libzstd parameter %d: %w", p[0], err)
		}
	}
	if len(dict) > 0 {
		// ZSTD_createCDict copies the dictionary.
		e.cdict = C.ZSTD_createCDict(unsafe.Pointer(&dict[0]), C.size_t(len(dict)), cLevel)
		if e.cdict == nil {
			e.close()
			return nil, errors.New("vault: libzstd rejected the dictionary")
		}
		if err := zstdErr(C.ZSTD_CCtx_refCDict(e.cctx, e.cdict)); err != nil {
			e.close()
			return nil, fmt.Errorf("vault: libzstd dictionary: %w", err)
		}
	}
	return e, nil
}

// encode returns src's frame; an error leaves nothing written anywhere.
func (e *cEncoder) encode(src []byte) ([]byte, error) {
	bound := C.ZSTD_compressBound(C.size_t(len(src)))
	dst := make([]byte, int(bound))
	var sp unsafe.Pointer
	if len(src) > 0 {
		sp = unsafe.Pointer(&src[0])
	}
	n := C.ZSTD_compress2(e.cctx, unsafe.Pointer(&dst[0]), bound, sp, C.size_t(len(src)))
	if err := zstdErr(n); err != nil {
		return nil, fmt.Errorf("vault: libzstd compression: %w", err)
	}
	return dst[:n], nil
}

func (e *cEncoder) close() {
	if e.cctx != nil {
		C.ZSTD_freeCCtx(e.cctx)
		e.cctx = nil
	}
	if e.cdict != nil {
		C.ZSTD_freeCDict(e.cdict)
		e.cdict = nil
	}
}

// zdictTrain runs libzstd's ZDICT_trainFromBuffer with capacity bytes of
// room. The dictionary's own ID is libzstd's automatic choice.
func zdictTrain(samples [][]byte, capacity int) ([]byte, error) {
	if len(samples) == 0 {
		return nil, errors.New("no samples")
	}
	var all []byte
	sizes := make([]C.size_t, len(samples))
	for i, s := range samples {
		all = append(all, s...)
		sizes[i] = C.size_t(len(s))
	}
	if len(all) == 0 {
		return nil, errors.New("empty samples")
	}
	dict := make([]byte, capacity)
	n := C.ZDICT_trainFromBuffer(unsafe.Pointer(&dict[0]), C.size_t(capacity), unsafe.Pointer(&all[0]), &sizes[0], C.unsigned(len(samples)))
	if C.ZDICT_isError(n) != 0 {
		return nil, errors.New(C.GoString(C.ZDICT_getErrorName(n)))
	}
	return dict[:n], nil
}
