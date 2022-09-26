package ocb

import (
	"bytes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"math/bits"

	"github.com/pedroalbanese/edgetk/ocb/byteutil"
)

type ocb struct {
	block        cipher.Block
	tagSize      int
	nonceSize    int
	mask         mask
	reusableKtop reusableKtop
}

type mask struct {
	lAst []byte
	lDol []byte
	L    [][]byte
}

type reusableKtop struct {
	noncePrefix []byte
	Ktop        []byte
}

const (
	defaultTagSize   = 16
	defaultNonceSize = 15
)

const (
	enc = iota
	dec
)

func (o *ocb) NonceSize() int {
	return o.nonceSize
}

func (o *ocb) Overhead() int {
	return o.tagSize
}

func NewOCB(block cipher.Block) (cipher.AEAD, error) {
	return NewOCBWithNonceAndTagSize(block, defaultNonceSize, defaultTagSize)
}

func NewOCBWithNonceAndTagSize(
	block cipher.Block, nonceSize, tagSize int) (cipher.AEAD, error) {
	if block.BlockSize() != 16 {
		return nil, ocbError("Block cipher must have 128-bit blocks")
	}
	if nonceSize < 1 {
		return nil, ocbError("Incorrect nonce length")
	}
	if nonceSize >= block.BlockSize() {
		return nil, ocbError("Nonce length exceeds blocksize - 1")
	}
	if tagSize > block.BlockSize() {
		return nil, ocbError("Custom tag length exceeds blocksize")
	}
	return &ocb{
		block:     block,
		tagSize:   tagSize,
		nonceSize: nonceSize,
		mask:      initializeMaskTable(block),
		reusableKtop: reusableKtop{
			noncePrefix: nil,
			Ktop:        nil,
		},
	}, nil
}

func (o *ocb) Seal(dst, nonce, plaintext, adata []byte) []byte {
	if len(nonce) > o.nonceSize {
		panic("crypto/ocb: Incorrect nonce length given to OCB")
	}
	ret, out := byteutil.SliceForAppend(dst, len(plaintext)+o.tagSize)
	o.crypt(enc, out, nonce, adata, plaintext)
	return ret
}

func (o *ocb) Open(dst, nonce, ciphertext, adata []byte) ([]byte, error) {
	if len(nonce) > o.nonceSize {
		panic("Nonce too long for this instance")
	}
	if len(ciphertext) < o.tagSize {
		return nil, ocbError("Ciphertext shorter than tag length")
	}
	sep := len(ciphertext) - o.tagSize
	ret, out := byteutil.SliceForAppend(dst, len(ciphertext))
	ciphertextData := ciphertext[:sep]
	tag := ciphertext[sep:]
	o.crypt(dec, out, nonce, adata, ciphertextData)
	if subtle.ConstantTimeCompare(ret[sep:], tag) == 1 {
		ret = ret[:sep]
		return ret, nil
	}
	for i := range out {
		out[i] = 0
	}
	return nil, ocbError("Tag authentication failed")
}

func (o *ocb) crypt(instruction int, Y, nonce, adata, X []byte) []byte {
	blockSize := o.block.BlockSize()

	truncatedNonce := make([]byte, len(nonce))
	copy(truncatedNonce, nonce)
	truncatedNonce[len(truncatedNonce)-1] &= 192
	Ktop := make([]byte, blockSize)
	if bytes.Equal(truncatedNonce, o.reusableKtop.noncePrefix) {
		Ktop = o.reusableKtop.Ktop
	} else {
		paddedNonce := append(make([]byte, blockSize-1-len(nonce)), 1)
		paddedNonce = append(paddedNonce, truncatedNonce...)
		paddedNonce[0] |= byte(((8 * o.tagSize) % (8 * blockSize)) << 1)
		paddedNonce[blockSize-1] &= 192
		Ktop = paddedNonce
		o.block.Encrypt(Ktop, Ktop)
		o.reusableKtop.noncePrefix = truncatedNonce
		o.reusableKtop.Ktop = Ktop
	}

	xorHalves := make([]byte, blockSize/2)
	byteutil.XorBytes(xorHalves, Ktop[:blockSize/2], Ktop[1:1+blockSize/2])
	stretch := append(Ktop, xorHalves...)
	bottom := int(nonce[len(nonce)-1] & 63)
	offset := make([]byte, len(stretch))
	byteutil.ShiftNBytesLeft(offset, stretch, bottom)
	offset = offset[:blockSize]

	checksum := make([]byte, blockSize)
	m := len(X) / blockSize
	for i := 0; i < m; i++ {
		index := bits.TrailingZeros(uint(i + 1))
		if len(o.mask.L)-1 < index {
			o.mask.extendTable(index)
		}
		byteutil.XorBytesMut(offset, o.mask.L[bits.TrailingZeros(uint(i+1))])
		blockX := X[i*blockSize : (i+1)*blockSize]
		blockY := Y[i*blockSize : (i+1)*blockSize]
		byteutil.XorBytes(blockY, blockX, offset)
		switch instruction {
		case enc:
			o.block.Encrypt(blockY, blockY)
			byteutil.XorBytesMut(blockY, offset)
			byteutil.XorBytesMut(checksum, blockX)
		case dec:
			o.block.Decrypt(blockY, blockY)
			byteutil.XorBytesMut(blockY, offset)
			byteutil.XorBytesMut(checksum, blockY)
		}
	}
	tag := make([]byte, blockSize)
	if len(X)%blockSize != 0 {
		byteutil.XorBytesMut(offset, o.mask.lAst)
		pad := make([]byte, blockSize)
		o.block.Encrypt(pad, offset)
		chunkX := X[blockSize*m:]
		chunkY := Y[blockSize*m : len(X)]
		byteutil.XorBytes(chunkY, chunkX, pad[:len(chunkX)])
		switch instruction {
		case enc:
			paddedY := append(chunkX, byte(128))
			paddedY = append(paddedY, make([]byte, blockSize-len(chunkX)-1)...)
			byteutil.XorBytesMut(checksum, paddedY)
		case dec:
			paddedX := append(chunkY, byte(128))
			paddedX = append(paddedX, make([]byte, blockSize-len(chunkY)-1)...)
			byteutil.XorBytesMut(checksum, paddedX)
		}
		byteutil.XorBytes(tag, checksum, offset)
		byteutil.XorBytesMut(tag, o.mask.lDol)
		o.block.Encrypt(tag, tag)
		byteutil.XorBytesMut(tag, o.hash(adata))
		copy(Y[blockSize*m+len(chunkY):], tag[:o.tagSize])
	} else {
		byteutil.XorBytes(tag, checksum, offset)
		byteutil.XorBytesMut(tag, o.mask.lDol)
		o.block.Encrypt(tag, tag)
		byteutil.XorBytesMut(tag, o.hash(adata))
		copy(Y[blockSize*m:], tag[:o.tagSize])
	}
	return Y
}

func (o *ocb) hash(adata []byte) []byte {
	A := make([]byte, len(adata))
	copy(A, adata)
	blockSize := o.block.BlockSize()

	sum := make([]byte, blockSize)
	offset := make([]byte, blockSize)
	m := len(A) / blockSize
	for i := 0; i < m; i++ {
		chunk := A[blockSize*i : blockSize*(i+1)]
		index := bits.TrailingZeros(uint(i + 1))
		if len(o.mask.L)-1 < index {
			o.mask.extendTable(index)
		}
		byteutil.XorBytesMut(offset, o.mask.L[index])
		byteutil.XorBytesMut(chunk, offset)
		o.block.Encrypt(chunk, chunk)
		byteutil.XorBytesMut(sum, chunk)
	}

	if len(A)%blockSize != 0 {
		byteutil.XorBytesMut(offset, o.mask.lAst)
		ending := make([]byte, blockSize-len(A)%blockSize)
		ending[0] = 0x80
		encrypted := append(A[blockSize*m:], ending...)
		byteutil.XorBytesMut(encrypted, offset)
		o.block.Encrypt(encrypted, encrypted)
		byteutil.XorBytesMut(sum, encrypted)
	}
	return sum
}

func initializeMaskTable(block cipher.Block) mask {
	lAst := make([]byte, block.BlockSize())
	block.Encrypt(lAst, lAst)
	lDol := byteutil.GfnDouble(lAst)
	L := make([][]byte, 1)
	L[0] = byteutil.GfnDouble(lDol)

	return mask{
		lAst: lAst,
		lDol: lDol,
		L:    L,
	}
}

func (m *mask) extendTable(limit int) {
	for i := len(m.L); i <= limit; i++ {
		m.L = append(m.L, byteutil.GfnDouble(m.L[i-1]))
	}
}

func ocbError(err string) error {
	return errors.New("crypto/ocb: " + err)
}
