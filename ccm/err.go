// Implement CCM as per RFC 3610 - https://tools.ietf.org/html/rfc3610
// Counter with CBC-MAC
//
// From: http://www.codeproject.com/Articles/21877/Applied-Crypto-Block-Ciphers
//
// "FIPS 81 specifies two MACs: CFB and CBC. CBC-MAC, which is based
// on DES, is a widely used algorithm to compute a message authentication
// code. CFB mode MACs are lesser known, and have some disadvantages
// compared to the CBC mode. CBC-MAC is now considered insecure for
// certain messages, such as those which vary in length. This has lead
// to the development of stronger MACs using 128 bit ciphers such as
// AES with a counter (RFC 3610). This is known as CCM, or Counter
// with CBC-MAC.'
//
// From: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ccm/ccm.pdf
//
// MIT Licensed
//

package ccm

import "errors"

var ErrTagSize = errors.New("CCM: TagSize must be one standard tag size of 4, 6, 8, 10, 12, 14, or 16")
var ErrInvalidBlockSize = errors.New("CCM: A 128-bit block cipher is mandatory")
var ErrNonceSize = errors.New("CCM: Invalid nonce size")
var ErrOpenError = errors.New("CCM: Message authentication failed")
var ErrCiphertextTooLong = errors.New("CCM: ciphertext exceeds maximum length")
var ErrCiphertextTooShort = errors.New("CCM: ciphertext below minimum length")
var ErrPlaintextTooLong = errors.New("CCM: plaintext exceeds maximum length")
var ErrInvalidNonceLength = errors.New("CCM: invalid nonce length")

/* vim: set noai ts=4 sw=4: */
