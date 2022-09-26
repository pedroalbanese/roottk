package byteutil

func GfnDouble(input []byte) []byte {
	if len(input) != 16 {
		panic("Doubling in GFn only implemented for n = 128")
	}
	shifted := ShiftBytesLeft(input)
	shifted[15] ^= ((input[0] >> 7) * 0x87)
	return shifted
}

func ShiftBytesLeft(x []byte) []byte {
	l := len(x)
	dst := make([]byte, l)
	for i := 0; i < l-1; i++ {
		dst[i] = (x[i] << 1) | (x[i+1] >> 7)
	}
	dst[l-1] = x[l-1] << 1
	return dst
}

func ShiftNBytesLeft(dst, x []byte, n int) {
	copy(dst, x[n/8:])

	bits := uint(n % 8)
	l := len(dst)
	for i := 0; i < l-1; i++ {
		dst[i] = (dst[i] << bits) | (dst[i+1] >> uint(8-bits))
	}
	dst[l-1] = dst[l-1] << bits

	dst = append(dst, make([]byte, n/8)...)
}

func XorBytesMut(X, Y []byte) {
	for i := 0; i < len(X); i++ {
		X[i] ^= Y[i]
	}
}

func XorBytes(Z, X, Y []byte) {
	for i := 0; i < len(X); i++ {
		Z[i] = X[i] ^ Y[i]
	}
}

func RightXor(X, Y []byte) []byte {
	offset := len(X) - len(Y)
	xored := make([]byte, len(X))
	copy(xored, X)
	for i := 0; i < len(Y); i++ {
		xored[offset+i] ^= Y[i]
	}
	return xored
}

func SliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
