package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/twofish"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"math/bits"
	mathrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"github.com/RyuaNerin/go-krypto/aria"
	"github.com/RyuaNerin/go-krypto/hight"
	"github.com/RyuaNerin/go-krypto/lea"
	"github.com/RyuaNerin/go-krypto/lsh256"
	"github.com/RyuaNerin/go-krypto/lsh512"
	"github.com/RyuaNerin/go-krypto/seed"
	"github.com/dgryski/go-anubis"
	"github.com/dgryski/go-kcipher2"
	"github.com/dsnet/compress/bzip2"
	"github.com/pedroalbanese/IGE-go/ige"
	"github.com/pedroalbanese/b85"
	"github.com/pedroalbanese/bb4"
	"github.com/pedroalbanese/blake256"
	"github.com/pedroalbanese/blake512"
	"github.com/pedroalbanese/bn"
	"github.com/pedroalbanese/brotli"
	"github.com/pedroalbanese/cmac"
	"github.com/pedroalbanese/crc24"
	"github.com/pedroalbanese/crypto/camellia"
	"github.com/pedroalbanese/crypto/hc128"
	"github.com/pedroalbanese/crypto/hc256"
	"github.com/pedroalbanese/crypto/serpent"
	"github.com/pedroalbanese/cubehash"
	"github.com/pedroalbanese/dos2unix"
	"github.com/pedroalbanese/eccrypt"
	"github.com/pedroalbanese/eccrypt/eccrypt160"
	"github.com/pedroalbanese/eccrypt/eccrypt192"
	"github.com/pedroalbanese/eccrypt/eccrypt512"
	"github.com/pedroalbanese/frp256v1"
	"github.com/pedroalbanese/gmsm/sm2"
	"github.com/pedroalbanese/gmsm/sm3"
	"github.com/pedroalbanese/gmsm/sm4"
	"github.com/pedroalbanese/gmtls"
	"github.com/pedroalbanese/go-a51"
	"github.com/pedroalbanese/go-chaskey"
	"github.com/pedroalbanese/go-crypto/brainpool"
	"github.com/pedroalbanese/go-crypto/salsa20"
	"github.com/pedroalbanese/go-crypto/tea"
	"github.com/pedroalbanese/go-crypto/xtea"
	"github.com/pedroalbanese/go-external-ip"
	"github.com/pedroalbanese/go-idea"
	"github.com/pedroalbanese/go-misty1"
	"github.com/pedroalbanese/go-rc5"
	"github.com/pedroalbanese/go-ripemd"
	"github.com/pedroalbanese/go-skip32"
	"github.com/pedroalbanese/go-skipjack"
	"github.com/pedroalbanese/go-twine"
	"github.com/pedroalbanese/gocurves"
	"github.com/pedroalbanese/gogost/gost28147"
	"github.com/pedroalbanese/gogost/gost3410"
	"github.com/pedroalbanese/gogost/gost34112012256"
	"github.com/pedroalbanese/gogost/gost34112012512"
	"github.com/pedroalbanese/gogost/gost341194"
	"github.com/pedroalbanese/gogost/gost3412128"
	"github.com/pedroalbanese/gogost/gost341264"
	"github.com/pedroalbanese/gogost/mgm"
	"github.com/pedroalbanese/golang-rc6"
	"github.com/pedroalbanese/gost-shred"
	"github.com/pedroalbanese/gost2001"
	"github.com/pedroalbanese/gost2012"
	"github.com/pedroalbanese/gostribog"
	"github.com/pedroalbanese/haraka"
	"github.com/pedroalbanese/isaac"
	"github.com/pedroalbanese/koblitz"
	"github.com/pedroalbanese/kuznechik"
	"github.com/pedroalbanese/lwcrypto/ascon2"
	"github.com/pedroalbanese/lwcrypto/grain"
	"github.com/pedroalbanese/lzma"
	"github.com/pedroalbanese/oakley192"
	"github.com/pedroalbanese/oakley256"
	"github.com/pedroalbanese/pearson"
	"github.com/pedroalbanese/pmac"
	"github.com/pedroalbanese/pmac/pmac64"
	"github.com/pedroalbanese/present"
	"github.com/pedroalbanese/prime192"
	"github.com/pedroalbanese/rabbitio"
	"github.com/pedroalbanese/radix64"
	"github.com/pedroalbanese/randomart"
	"github.com/pedroalbanese/roottk/ccm"
	"github.com/pedroalbanese/roottk/eax"
	"github.com/pedroalbanese/roottk/groestl"
	"github.com/pedroalbanese/roottk/jh"
	"github.com/pedroalbanese/roottk/ocb"
	"github.com/pedroalbanese/roottk/threefish"
	"github.com/pedroalbanese/rtea"
	"github.com/pedroalbanese/seahash"
	"github.com/pedroalbanese/sealion"
	"github.com/pedroalbanese/seaturtle"
	"github.com/pedroalbanese/secp112r1"
	"github.com/pedroalbanese/secp128r1"
	"github.com/pedroalbanese/secp160r1"
	"github.com/pedroalbanese/secp160r2"
	"github.com/pedroalbanese/shannon"
	"github.com/pedroalbanese/simonspeck"
	"github.com/pedroalbanese/simpleini"
	"github.com/pedroalbanese/siphash"
	"github.com/pedroalbanese/siv"
	"github.com/pedroalbanese/skein"
	"github.com/pedroalbanese/skein/skein256"
	"github.com/pedroalbanese/snow3g"
	"github.com/pedroalbanese/snow3g/uea2"
	"github.com/pedroalbanese/snow3g/uia2"
	"github.com/pedroalbanese/tiger"
	"github.com/pedroalbanese/tiger/tiger128"
	"github.com/pedroalbanese/tiger/tiger160"
	"github.com/pedroalbanese/trivium"
	"github.com/pedroalbanese/wapi"
	"github.com/pedroalbanese/whirlpool"
	"github.com/pedroalbanese/wtls"
	"github.com/pedroalbanese/zuc"
	"github.com/pedroalbanese/zuc/eea3"
	"github.com/pedroalbanese/zuc/eia3"
	"github.com/zeebo/blake3"
	CFB8 "github.com/pedroalbanese/roottk/cfb8"
	b32 "encoding/base32"
	b64 "encoding/base64"
	c509 "github.com/pedroalbanese/gmsm/x509"
	groestl512 "github.com/pedroalbanese/groestl"
	passwordvalidator "github.com/pedroalbanese/go-password-validator"
	skeincipher "github.com/pedroalbanese/skein-1"
	sm2p256v1 "github.com/pedroalbanese/sm2"
	sm9p256v1 "github.com/pedroalbanese/sm9"
	zuc2 "github.com/emmansun/gmsm/zuc"
)

var (
	alg     = flag.String("algorithm", "ecdsa", "Asymmetric algorithm: brainpool256r1, ecdsa, sm2.")
	check   = flag.String("check", "", "Check hashsum file. ('-' for STDIN)")
	cph     = flag.String("cipher", "aes", "Symmetric algorithm, e.g. aes, serpent, twofish.")
	crypt   = flag.String("crypt", "", "Encrypt/Decrypt with bulk ciphers.")
	del     = flag.String("shred", "", "Target file/path/wildcard to apply data sanitization method.")
	info    = flag.String("info", "", "Associated data, additional info. (for HKDF and AEAD encryption)")
	iter    = flag.Int("iter", 1, "Iterations. (for KDF and SHRED commands)")
	kdf     = flag.String("kdf", "", "Password-based key derivation function: HKDF, PBKDF2 or Scrypt.")
	key     = flag.String("key", "", "Private/Public key, password or HMAC key, depending on operation.")
	keygen  = flag.Bool("keygen", false, "Generate asymmetric keypair.")
	length  = flag.Int("bits", 256, "Key length: 64, 128, 192 or 256. (for RAND and KDF)")
	list    = flag.Bool("list", false, "List all available algorithms.")
	mac     = flag.String("mac", "", "Compute Cipher-based/Hash-based message authentication code.")
	md      = flag.String("md", "sha256", "Hash algorithm, e.g. sha256, sm3 or keccak256.")
	mode    = flag.String("mode", "CTR", "Mode of operation: CCM, GCM, MGM, OCB, EAX or OFB.")
	pkeyutl = flag.String("pkeyutl", "", "Derive or Encrypt/Decrypt with asymmetric algorithms.")
	public  = flag.String("pub", "", "Remote's side public key/Public IP/Local Port. (for ECDH and TLS)")
	random  = flag.Bool("rand", false, "Generate random cryptographic key.")
	rec     = flag.Bool("recursive", false, "Process directories recursively. (for DIGEST command only)")
	salt    = flag.String("salt", "", "Salt. (for KDF only)")
	sig     = flag.String("signature", "", "Input signature. (verification only)")
	sign    = flag.Bool("sign", false, "Sign hash with Private key.")
	target  = flag.String("digest", "", "Target file/wildcard to generate hashsum list. ('-' for STDIN)")
	tcpip   = flag.String("tcp", "", "Encrypted TCP/IP Transfer Protocol. [dump|listen|ip|send|dial]")
	util    = flag.String("util", "", "Utilities for encoding and compression. (type -util help)")
	vector  = flag.String("iv", "", "Initialization vector. (for symmetric encryption)")
	verify  = flag.Bool("verify", false, "Verify signature with Public key.")
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *sm2.PrivateKey:
		return k.Public()
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	case *rsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func handleConnection(c net.Conn) {
	log.Printf("Client(TLS) %v connected via secure channel.", c.RemoteAddr())
	log.Printf("Connection from %v closed.", c.RemoteAddr())
}

func main() {
	flag.Parse()
	start := time.Now()

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *length != 32 && *length != 40 && *length != 64 && *length != 80 && *length != 96 && *length != 112 && *length != 128 && *length != 160 && *length != 184 && *length != 192 && *length != 224 && *length != 256 && *length != 320 && *length != 448 && *length != 512 && *length != 1024 {
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *util == "list" || *list {
		fmt.Fprintln(os.Stderr, "EDGE Toolkit: Security Suite CLI v1.2.3 - ALBANESE Research Lab\n")
		fmt.Fprintln(os.Stderr, "Public Key Algorithms:")
		fmt.Fprintln(os.Stderr, "  gost2001          brainpool256r1    oakley192")
		fmt.Fprintln(os.Stderr, "  gost2001B         brainpool256t1    oakley256")
		fmt.Fprintln(os.Stderr, "  gost2001C         brainpool512r1    prime192v1")
		fmt.Fprintln(os.Stderr, "  gost2001XA        brainpool512t1    prime192v2")
		fmt.Fprintln(os.Stderr, "  gost2001XB        brainpool192t1    prime192v3")
		fmt.Fprintln(os.Stderr, "  gost2012_256      brainpool160t1    secp160r1")
		fmt.Fprintln(os.Stderr, "  gost2012_256B     ed25519/X25519    secp160r2")
		fmt.Fprintln(os.Stderr, "  gost2012_256C     fp256bn           secp160k1")
		fmt.Fprintln(os.Stderr, "  gost2012_256D     fp512bn           secp192k1")
		fmt.Fprintln(os.Stderr, "  gost2012_512      frp256v1          secp256k1")
		fmt.Fprintln(os.Stderr, "  gost2012_512B     numsp256d1        sm2")
		fmt.Fprintln(os.Stderr, "  gost2012_512C     numsp512d1        sm9p256v1\n")
		fmt.Fprintln(os.Stderr, "Stream Ciphers:")
		fmt.Fprintln(os.Stderr, "  ascon (AEAD)      grain (AEAD)      trivium")
		fmt.Fprintln(os.Stderr, "  uea2              chacha20 (AEAD)   hc128")
		fmt.Fprintln(os.Stderr, "  eea3              salsa20           hc256")
		fmt.Fprintln(os.Stderr, "  rabbit            shannon (AE)      skein\n")
		fmt.Fprintln(os.Stderr, "Block Ciphers:")
		fmt.Fprintln(os.Stderr, "  aes (default)     seed              twofish")
		fmt.Fprintln(os.Stderr, "  aria              serpent           threefish256")
		fmt.Fprintln(os.Stderr, "  camellia          simon128          threefish512")
		fmt.Fprintln(os.Stderr, "  grasshopper       speck128          threefish1024")
		fmt.Fprintln(os.Stderr, "  rc6               sm4               3des")
		fmt.Fprintln(os.Stderr, "  rc5               lea               idea")
		fmt.Fprintln(os.Stderr, "  gost89            magma             simon64")
		fmt.Fprintln(os.Stderr, "  blowfish          misty1            speck64")
		fmt.Fprintln(os.Stderr, "  cast5             present           tea")
		fmt.Fprintln(os.Stderr, "  hight             twine             xtea\n")
		fmt.Fprintln(os.Stderr, "Modes of Operation:")
		fmt.Fprintln(os.Stderr, "  CTR (default)     OFB               CFB8")
		fmt.Fprintln(os.Stderr, "  CCM (AEAD)        EAX (AEAD)        GCM (AEAD)")
		fmt.Fprintln(os.Stderr, "  MGM (AEAD)        OCB (AEAD)        SIV (AEAD)\n")
		fmt.Fprintln(os.Stderr, "Message Digest Algorithms:")
		fmt.Fprintln(os.Stderr, "  blake256          keccak256         sha512")
		fmt.Fprintln(os.Stderr, "  blake512          keccak512         sha3_256")
		fmt.Fprintln(os.Stderr, "  blake2b256        haraka            sha3_512")
		fmt.Fprintln(os.Stderr, "  blake2b512        lsh256            poly1305")
		fmt.Fprintln(os.Stderr, "  blake2s128        lsh512_256        skein256")
		fmt.Fprintln(os.Stderr, "  blake2s256        lsh512            skein512_256")
		fmt.Fprintln(os.Stderr, "  blake3            md5               skein512")
		fmt.Fprintln(os.Stderr, "  siphash           rmd128            sm3")
		fmt.Fprintln(os.Stderr, "  cubehash          rmd160            streebog256")
		fmt.Fprintln(os.Stderr, "  groestl           rmd256            streebog512")
		fmt.Fprintln(os.Stderr, "  groestl512        sha1              tiger")
		fmt.Fprintln(os.Stderr, "  gost94            sha256 (default)  tiger2")
		fmt.Fprintln(os.Stderr, "  jh                sha512_256        whirlpool")
		fmt.Fprintln(os.Stderr, "\nCopyright (c) 2020-2022, Pedro F. Albanese. All rights reserved.")
		os.Exit(0)
	}

	if *util == "help" {
		fmt.Fprintln(os.Stderr, "EDGE Toolkit: Security Suite CLI v1.2.3 - ALBANESE Research Lab\n")
		fmt.Fprintln(os.Stderr, "UTIL Subcommands:")
		fmt.Fprintln(os.Stderr, "  Base32 Encoding ....: -util [b32enc|b32dec] < input.ext > output.ext")
		fmt.Fprintln(os.Stderr, "  Base64 Encoding ....: -util [b64enc|b64dec] < input.ext > output.ext")
		fmt.Fprintln(os.Stderr, "  Hex Encoding .......: -util [hexenc|hexdec] < input.ext > output.ext")
		fmt.Fprintln(os.Stderr, "  Compress/Decompress : -util [compress|decompress] < input.ext > output.ext")
		fmt.Fprintln(os.Stderr, "  Random Art .........: -util fingerprint -key \"-\" < pubkey.txt")
		fmt.Fprintln(os.Stderr, "  Split Key in Chunks : -util sliptkey+ -key \"-\" < key.txt > split.txt")
		fmt.Fprintln(os.Stderr, "  Join Key Chunks ....: -util joinkey < split.txt")
		fmt.Fprintln(os.Stderr, "  Password Generator .: -util pwgen [-bits 96] > passwd.txt")
		fmt.Fprintln(os.Stderr, "  Password Validator .: -util entropy -key \"-\" < passwd.txt\n")
		fmt.Fprintln(os.Stderr, "Try:")
		fmt.Fprintln(os.Stderr, "  ./roottk -util pwgen -bits 80|./roottk -util entropy -key -")
		fmt.Fprintln(os.Stderr, "  echo $?            / at Linux")
		fmt.Fprintln(os.Stderr, "  echo %ERRORLEVEL%  / at Windows\n")
		fmt.Fprintln(os.Stderr, "  Passwords must have at least 64-bit of entropy, otherwise exit code is 1.")
		fmt.Fprintln(os.Stderr, "\nCopyright (c) 2020-2022, Pedro F. Albanese. All rights reserved.")
		os.Exit(0)
	}

	if (*cph == "sm4" || *cph == "hight" || *cph == "idea" || *cph == "cast5" || *cph == "rc5" || *cph == "tea" || *cph == "xtea" || *cph == "xtea" || *cph == "rtea" || *cph == "simon64" || *cph == "speck64" || *cph == "present" || *cph == "twine" || *cph == "misty1") && (*length != 64 && *length != 80 && *length != 96 && *length != 128) {
		*length = 128
	} else if *cph == "3des" && (*length != 96 && *length != 192) {
		*length = 192
	} else if *cph == "skipjack" && (*length != 40 && *length != 80) {
		*length = 80
	} else if (*cph == "simon32" || *cph == "speck32") && (*length != 64) {
		*length = 64
	} else if (*mac == "eia256") && (*length != 32 && *length != 64 && *length != 128) {
		*length = 128
	}

	var myHash func() hash.Hash
	if *md == "sha256" {
		myHash = sha256.New
	} else if *md == "sha512" {
		myHash = sha512.New
	} else if *md == "sha512_256" {
		myHash = sha512.New512_256
	} else if *md == "md5" {
		myHash = md5.New
	} else if *md == "sha1" {
		myHash = sha1.New
	} else if *md == "rmd128" {
		myHash = ripemd.New128
	} else if *md == "rmd160" {
		myHash = ripemd.New160
	} else if *md == "rmd256" {
		myHash = ripemd.New256
	} else if *md == "sha3_256" {
		myHash = sha3.New256
	} else if *md == "sha3_512" {
		myHash = sha3.New512
	} else if *md == "keccak256" {
		myHash = sha3.NewLegacyKeccak256
	} else if *md == "keccak512" {
		myHash = sha3.NewLegacyKeccak512
	} else if *md == "whirlpool" {
		myHash = whirlpool.New
	} else if *md == "blake256" {
		myHash = blake256.New
	} else if *md == "blake512" {
		myHash = blake512.New
	} else if *md == "blake2b256" {
		myHash = crypto.BLAKE2b_256.New
	} else if *md == "blake2b512" {
		myHash = crypto.BLAKE2b_512.New
	} else if *md == "blake2s256" {
		myHash = crypto.BLAKE2s_256.New
	} else if *md == "skein256" {
		g := func() hash.Hash {
			return skein256.New256(nil)
		}
		myHash = g
	} else if *md == "skein512_256" {
		g := func() hash.Hash {
			return skein.New256(nil)
		}
		myHash = g
	} else if *md == "skein512" {
		g := func() hash.Hash {
			return skein.New512(nil)
		}
		myHash = g
	} else if *md == "seahash" {
		g := func() hash.Hash {
			return seahash.New()
		}
		myHash = g
	} else if *md == "djb" {
		g := func() hash.Hash {
			return NewDjb32()
		}
		myHash = g
	} else if *md == "djba" {
		g := func() hash.Hash {
			return NewDjb32a()
		}
		myHash = g
	} else if *md == "sdbm" {
		g := func() hash.Hash {
			return NewSDBM32()
		}
		myHash = g
	} else if *md == "elf32" {
		g := func() hash.Hash {
			return NewElf32()
		}
		myHash = g
	} else if *md == "8-bit" {
		g := func() hash.Hash {
			return pearson.New()
		}
		myHash = g
	} else if *md == "crc24" {
		g := func() hash.Hash {
			return crc24.New()
		}
		myHash = g
	} else if *md == "groestl" {
		myHash = groestl.New256
	} else if *md == "groestl512" {
		myHash = groestl512.New512
	} else if *md == "jh" {
		myHash = jh.New256
	} else if *md == "tiger" {
		myHash = tiger.New
	} else if *md == "tiger128" {
		myHash = tiger128.New
	} else if *md == "tiger160" {
		myHash = tiger160.New
	} else if *md == "tiger2" {
		myHash = tiger.New2
	} else if *md == "tiger2_128" {
		myHash = tiger128.New2
	} else if *md == "tiger2_160" {
		myHash = tiger160.New2
	} else if *md == "sm3" {
		myHash = sm3.New
	} else if *md == "gost94" {
		g := func() hash.Hash {
			return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		}
		myHash = g
	} else if *md == "streebog256" {
		myHash = gost34112012256.New
	} else if *md == "streebog512" {
		myHash = gost34112012512.New
	} else if *md == "stribog256" {
		myHash = gostribog.New256
	} else if *md == "stribog512" {
		myHash = gostribog.New512
	} else if *md == "lsh256" {
		myHash = lsh256.New
	} else if *md == "lsh512" {
		myHash = lsh512.New
	} else if *md == "lsh512_256" {
		myHash = lsh512.New256
	} else if *md == "blake3" {
		g := func() hash.Hash {
			return blake3.New()
		}
		myHash = g
	} else if *md == "cubehash" {
		myHash = cubehash.New
	}

	var h hash.Hash
	if *md == "sha256" {
		h = sha256.New()
	} else if *md == "sha512" {
		h = sha512.New()
	} else if *md == "sha512_256" {
		h = sha512.New512_256()
	} else if *md == "md5" {
		h = md5.New()
	} else if *md == "sha1" {
		h = sha1.New()
	} else if *md == "rmd128" {
		h = ripemd.New128()
	} else if *md == "rmd160" {
		h = ripemd.New160()
	} else if *md == "rmd256" {
		h = ripemd.New256()
	} else if *md == "sha3_256" {
		h = sha3.New256()
	} else if *md == "sha3_512" {
		h = sha3.New512()
	} else if *md == "keccak256" {
		h = sha3.NewLegacyKeccak256()
	} else if *md == "keccak512" {
		h = sha3.NewLegacyKeccak512()
	} else if *md == "whirlpool" {
		h = whirlpool.New()
	} else if *md == "blake256" {
		h = blake256.New()
	} else if *md == "blake512" {
		h = blake512.New()
	} else if *md == "blake2b256" {
		h, _ = blake2b.New256(nil)
	} else if *md == "blake2b512" {
		h, _ = blake2b.New512(nil)
	} else if *md == "blake2s256" {
		h, _ = blake2s.New256(nil)
	} else if *md == "skein256" {
		h = skein256.New256(nil)
	} else if *md == "skein512_256" {
		h = skein.New256(nil)
	} else if *md == "skein512" {
		h = skein.New512(nil)
	} else if *md == "groestl" {
		h = groestl.New256()
	} else if *md == "groestl512" {
		h = groestl512.New512()
	} else if *md == "jh" {
		h = jh.New256()
	} else if *md == "tiger" {
		h = tiger.New()
	} else if *md == "tiger128" {
		h = tiger128.New()
	} else if *md == "tiger160" {
		h = tiger160.New()
	} else if *md == "tiger2" {
		h = tiger.New2()
	} else if *md == "tiger2_128" {
		h = tiger128.New2()
	} else if *md == "tiger2_160" {
		h = tiger160.New2()
	} else if *md == "sm3" {
		h = sm3.New()
	} else if *md == "gost94" {
		h = gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
	} else if *md == "streebog256" {
		h = gost34112012256.New()
	} else if *md == "streebog512" {
		h = gost34112012512.New()
	} else if *md == "stribog256" {
		h = gostribog.New256()
	} else if *md == "stribog512" {
		h = gostribog.New512()
	} else if *md == "lsh256" {
		h = lsh256.New()
	} else if *md == "lsh512" {
		h = lsh512.New()
	} else if *md == "lsh512_256" {
		h = lsh512.New256()
	} else if *md == "blake3" {
		h = blake3.New()
	} else if *md == "blake3" {
		h = cubehash.New()
	}

	if *random {
		var key []byte
		var err error
		key = make([]byte, *length/8)
		_, err = io.ReadFull(rand.Reader, key)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(key))
		os.Exit(0)
	}

	if *util == "b64enc" {
		data, _ := ioutil.ReadAll(os.Stdin)
		b := strings.TrimSuffix(string(data), "\r\n")
		b = strings.TrimSuffix(b, "\n")
		sEnc := b64.StdEncoding.EncodeToString([]byte(b))
		for _, chunk := range split(sEnc, 64) {
			fmt.Println(chunk)
		}
	} else if *util == "b64dec" {
		data, _ := ioutil.ReadAll(os.Stdin)
		b := strings.TrimSuffix(string(data), "\r\n")
		b = strings.TrimSuffix(b, "\n")
		sDec, _ := b64.StdEncoding.DecodeString(b)
		os.Stdout.Write(sDec)
	}

	if *util == "b64enc+" {
		data, _ := ioutil.ReadAll(os.Stdin)
		b := strings.TrimSuffix(string(data), "\r\n")
		b = strings.TrimSuffix(b, "\n")
		sEnc := b64.RawStdEncoding.EncodeToString([]byte(b))
		for _, chunk := range split(sEnc, 64) {
			fmt.Println(chunk)
		}
	} else if *util == "b64dec+" {
		data, _ := ioutil.ReadAll(os.Stdin)
		b := strings.TrimSuffix(string(data), "\r\n")
		b = strings.TrimSuffix(b, "\n")
		sDec, _ := b64.RawStdEncoding.DecodeString(b)
		os.Stdout.Write(sDec)
	}

	if *util == "b32enc" {
		data, _ := ioutil.ReadAll(os.Stdin)
		b := strings.TrimSuffix(string(data), "\r\n")
		b = strings.TrimSuffix(b, "\n")
		sEnc := b32.StdEncoding.EncodeToString([]byte(b))
		for _, chunk := range split(sEnc, 64) {
			fmt.Println(chunk)
		}
	} else if *util == "b32dec" {
		data, _ := ioutil.ReadAll(os.Stdin)
		b := strings.TrimSuffix(string(data), "\r\n")
		b = strings.TrimSuffix(b, "\n")
		sDec, _ := b32.StdEncoding.DecodeString(b)
		os.Stdout.Write(sDec)
	}

	if *util == "b32enc+" {
		data, _ := ioutil.ReadAll(os.Stdin)
		b := strings.TrimSuffix(string(data), "\r\n")
		b = strings.TrimSuffix(b, "\n")
		sEnc := b32.StdEncoding.WithPadding(-1).EncodeToString([]byte(b))
		for _, chunk := range split(sEnc, 64) {
			fmt.Println(chunk)
		}
	} else if *util == "b32dec+" {
		data, _ := ioutil.ReadAll(os.Stdin)
		b := strings.TrimSuffix(string(data), "\r\n")
		b = strings.TrimSuffix(b, "\n")
		sDec, _ := b32.StdEncoding.WithPadding(-1).DecodeString(b)
		os.Stdout.Write(sDec)
	}

	if *util == "splitkey" && *key != "-" {
		print(len(*key)/2, " bytes ", len(*key)*4, " bits\n")
		splitx := SplitSubN(*key, 4)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitx), "[]"), 40) {
			fmt.Println(strings.ToUpper(chunk))
		}
	} else if *util == "splitkey" && *key == "-" {
		data, _ := ioutil.ReadAll(os.Stdin)
		b := strings.TrimSuffix(string(data), "\r\n")
		b = strings.TrimSuffix(b, "\n")
		print(len(b)/2, " bytes ", len(b)*4, " bits\n")
		splitx := SplitSubN(b, 4)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitx), "[]"), 40) {
			fmt.Println(strings.ToUpper(chunk))
		}
	}

	if *util == "splitkey+" && *key != "-" {
		print(len(*key)/2, " bytes ", len(*key)*4, " bits\n")
		splitx := SplitSubN(*key, 4)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitx), "[]"), 80) {
			fmt.Println(strings.ToUpper(chunk))
		}
	} else if *util == "splitkey+" && *key == "-" {
		data, _ := ioutil.ReadAll(os.Stdin)
		b := strings.TrimSuffix(string(data), "\r\n")
		b = strings.TrimSuffix(b, "\n")
		print(len(b)/2, " bytes ", len(b)*4, " bits\n")
		splitx := SplitSubN(b, 4)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitx), "[]"), 80) {
			fmt.Println(strings.ToUpper(chunk))
		}
	}

	if *util == "joinkey" {
		data, _ := ioutil.ReadAll(os.Stdin)
		join := strings.ReplaceAll(string(data), " ", "")
		join = strings.ReplaceAll(join, "\r\n", "")
		join = strings.ReplaceAll(join, "\n", "")
		fmt.Println(strings.ToLower(join))
	}

	if *util == "entropy" && *key != "-" {
		entropy := passwordvalidator.GetEntropy(*key)
		const minEntropyBits = 128
		err := passwordvalidator.Validate(*key, minEntropyBits)
		fmt.Fprintln(os.Stderr, len(*key), "bytes", len(*key)*8, "bits")
		fmt.Fprintln(os.Stderr, "Passwd=", *key)
		fmt.Fprintln(os.Stderr, "Entropy=", entropy)
		if err != nil {
			log.Fatal(err)
		}
	} else if *util == "entropy" && *key == "-" {
		data, _ := ioutil.ReadAll(os.Stdin)
		b := strings.TrimSuffix(string(data), "\r\n")
		b = strings.TrimSuffix(b, "\n")
		entropy := passwordvalidator.GetEntropy(b)
		const minEntropyBits = 128
		err := passwordvalidator.Validate(b, minEntropyBits)
		fmt.Fprintln(os.Stderr, len(b), "bytes", len(b)*8, "bits")
		fmt.Fprintln(os.Stderr, "Passwd=", b)
		fmt.Fprintln(os.Stderr, "Entropy=", entropy)
		if err != nil {
			log.Fatal(err)
		}
	}

	if *util == "pwgen" {
		mathrand.Seed(time.Now().UnixNano())
		fmt.Println(randSeq(*length / 8))
	}

	if *util == "b85enc" {
		data, _ := ioutil.ReadAll(os.Stdin)
		b := strings.TrimSuffix(string(data), "\r\n")
		b = strings.TrimSuffix(b, "\n")
		sEnc := b85.Encode([]byte(b))
		for _, chunk := range split(sEnc, 64) {
			fmt.Println(chunk)
		}
	} else if *util == "b85dec" {
		data, _ := ioutil.ReadAll(os.Stdin)
		b := strings.TrimSuffix(string(data), "\r\n")
		b = strings.TrimSuffix(b, "\n")
		sDec, _ := b85.Decode(b)
		os.Stdout.Write(sDec)
	}

	if *util == "hexenc" {
		b, err := ioutil.ReadAll(os.Stdin)
		if len(b) == 0 {
			os.Exit(0)
		}
		if err != nil {
			log.Fatal(err)
		}
		o := make([]byte, hex.EncodedLen(len(b)))
		hex.Encode(o, b)
		os.Stdout.Write(o)
		os.Exit(0)
	} else if *util == "hexdec" {
		var err error
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		b := strings.TrimSuffix(string(buf.Bytes()), "\r\n")
		b = strings.TrimSuffix(string(b), "\n")
		if len(b) == 0 {
			os.Exit(0)
		}
		if len(b) < 2 {
			os.Exit(0)
		}
		if (len(b)%2 != 0) || (err != nil) {
			log.Fatal(err)
		}
		o := make([]byte, hex.DecodedLen(len(b)))
		_, err = hex.Decode(o, []byte(b))
		if err != nil {
			log.Fatal(err)
		}
		os.Stdout.Write(o)
		os.Exit(0)
	} else if *util == "hexdump" {
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		b := strings.TrimSuffix(string(buf.Bytes()), "\r\n")
		b = strings.TrimSuffix(string(b), "\n")
		dump := hex.Dump([]byte(b))
		os.Stdout.Write([]byte(dump))
		os.Exit(0)
	}

	if *util == "atbash" {
		data, _ := ioutil.ReadAll(os.Stdin)
		fmt.Print(atbash(string(data)))
	}

	if *util == "rot13" {
		data, _ := ioutil.ReadAll(os.Stdin)
		fmt.Print(rot13(string(data)))
	}

	if *util == "unix2dos" {
		io.Copy(os.Stdout, dos2unix.Unix2DOS(os.Stdin))
	}

	if *util == "dos2unix" {
		io.Copy(os.Stdout, dos2unix.DOS2Unix(os.Stdin))
	}

	if (*crypt == "enc" || *crypt == "dec") && *cph == "chaocipher" {
		data, _ := ioutil.ReadAll(os.Stdin)
		b := strings.TrimSuffix(string(data), "\r\n")
		b = strings.TrimSuffix(b, "\n")
		b = strings.ToUpper(b)
		if *crypt == "enc" {
			cipherText := Chao(string(b), Encrypt, true)
			fmt.Println(cipherText)
		} else {
			plainText := Chao(string(b), Decrypt, true)
			fmt.Println(plainText)
		}
	}

	if *util == "compress" || *util == "decompress" {
		pr, pw := io.Pipe()
		defer pr.Close()
		defer pw.Close()

		var algorithm string
		if *alg == "gzip" || *alg == "brotli" || *alg == "zlib" || *alg == "bzip2" {
			algorithm = *alg
		} else {
			algorithm = "lzma"
		}
		if *util == "decompress" {
			go func() {
				defer pw.Close()
				var inFile *os.File
				var err error
				inFile = os.Stdin
				defer inFile.Close()
				if err != nil {
					log.Fatal(err.Error())
				}

				_, err = io.Copy(pw, inFile)
				if err != nil {
					log.Fatal(err.Error())
				}

			}()

			defer pr.Close()
			if algorithm == "lzma" {
				z := lzma.NewReader(pr)
				var outFile *os.File
				var err error
				outFile = os.Stdout
				defer outFile.Close()
				if err != nil {
					log.Fatal(err.Error())
				}

				_, err = io.Copy(outFile, z)
				if err != nil {
					log.Fatal(err.Error())
				}
			} else if algorithm == "gzip" {
				z, _ := gzip.NewReader(pr)
				var outFile *os.File
				var err error
				outFile = os.Stdout
				defer outFile.Close()
				if err != nil {
					log.Fatal(err.Error())
				}

				_, err = io.Copy(outFile, z)
				if err != nil {
					log.Fatal(err.Error())
				}
			} else if algorithm == "brotli" {
				z := brotli.NewReader(pr)
				var outFile *os.File
				var err error
				outFile = os.Stdout
				defer outFile.Close()
				if err != nil {
					log.Fatal(err.Error())
				}

				_, err = io.Copy(outFile, z)
				if err != nil {
					log.Fatal(err.Error())
				}
			} else if algorithm == "zlib" {
				z, _ := zlib.NewReader(pr)
				var outFile *os.File
				var err error
				outFile = os.Stdout
				defer outFile.Close()
				if err != nil {
					log.Fatal(err.Error())
				}

				_, err = io.Copy(outFile, z)
				if err != nil {
					log.Fatal(err.Error())
				}
			} else if algorithm == "bzip2" {
				z, _ := bzip2.NewReader(pr, nil)
				var outFile *os.File
				var err error
				outFile = os.Stdout
				defer outFile.Close()
				if err != nil {
					log.Fatal(err.Error())
				}

				_, err = io.Copy(outFile, z)
				if err != nil {
					log.Fatal(err.Error())
				}
			}

		} else if *util == "compress" {
			go func() {
				defer pw.Close()
				var z io.WriteCloser
				var inFile *os.File
				var err error
				inFile = os.Stdin
				defer inFile.Close()
				if algorithm == "lzma" {
					z = lzma.NewWriter(pw)
				} else if algorithm == "gzip" {
					z = gzip.NewWriter(pw)
				} else if algorithm == "brotli" {
					z = brotli.NewWriter(pw)
				} else if algorithm == "zlib" {
					z = zlib.NewWriter(pw)
				} else if algorithm == "bzip2" {
					z, _ = bzip2.NewWriter(pw, nil)
				}
				defer z.Close()

				_, err = io.Copy(z, inFile)
				if err != nil {
					log.Fatal(err.Error())
				}
			}()

			defer pr.Close()
			var outFile *os.File
			var err error
			outFile = os.Stdout
			defer outFile.Close()
			if err != nil {
				log.Fatal(err.Error())
			}

			_, err = io.Copy(outFile, pr)
			if err != nil {
				log.Fatal(err.Error())
			}
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *util == "radixenc" || *util == "radixdec" {
		if *util == "radixenc" {
			b, _ := ioutil.ReadAll(os.Stdin)
			d := strings.TrimSuffix(string(b), "\r\n")
			d = strings.TrimSuffix(d, "\n")
			g, _ := strconv.ParseUint(d, 0, 64)
			m := uint64(g)
			if m > 0 {
				b := make([]byte, 10)
				_ = radix64.Encode(m, b)
				fmt.Println(string(b))
			}
			os.Exit(0)
		} else {
			b, _ := ioutil.ReadAll(os.Stdin)
			d := strings.TrimSuffix(string(b), "\r\n")
			d = strings.TrimSuffix(d, "\n")
			n, _ := radix64.Decode([]byte(d))
			fmt.Println(n)
			os.Exit(0)
		}
	}

	if *crypt != "" && *cph == "isaac" {
		var keyHex string
		var prvRaw []byte
		if *kdf == "pbkdf2" {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, sha256.New)
			keyHex = hex.EncodeToString(prvRaw)
		} else {
			keyHex = *key
		}
		var err error

		buf := make([]byte, 128*1<<10)
		ciph := isaac.NewISAACStream(keyHex)
		var n int
		for {
			n, err = os.Stdin.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *crypt != "" && (*cph == "skip32") {
		if *key == "" {
			log.Fatal("Skip32 needs a 40-bit key.")
		}
		obfu, _ := skip32.New([]byte(*key))
		if *crypt == "enc" {
			b, _ := ioutil.ReadAll(os.Stdin)
			d := strings.TrimSuffix(string(b), "\r\n")
			d = strings.TrimSuffix(d, "\n")
			g, _ := strconv.ParseUint(d, 0, 32)
			m := uint32(g)
			if m > 2147483647 {
				log.Fatal("int exceeds 2.147.483.647 (eighth Prime of Mersenne 2^31)")
				os.Exit(1)
			}
			c := obfu.Obfus(m)

			if CountDigits(int(c)) < 10 {
				fmt.Printf("%0*d\n", 10, c)
			} else {
				fmt.Println(c)
			}
			os.Exit(0)
		} else {
			b, _ := ioutil.ReadAll(os.Stdin)
			d := strings.TrimSuffix(string(b), "\r\n")
			d = strings.TrimSuffix(d, "\n")
			c := strings.TrimPrefix(d, "00")
			c = strings.TrimPrefix(c, "0")
			c = strings.TrimPrefix(c, "0")
			g, _ := strconv.ParseUint(c, 0, 32)
			if g < 1 {
				log.Fatal("no input")
			}
			m := uint32(g)
			p := obfu.Unobfus(m)
			fmt.Println(int(p))
			os.Exit(0)
		}
	}

	if *crypt != "" && *cph == "kcipher2" {
		var keyHex string
		var prvRaw []byte
		if *kdf == "pbkdf2" {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, myHash)
			keyHex = hex.EncodeToString(prvRaw)
		} else {
			keyHex = *key
		}
		var key []byte
		var err error
		if keyHex != "" {
			key, _ := hex.DecodeString(keyHex)
			if len(key) != 16 {
				log.Fatal(err)
			}
		} else {
			key = make([]byte, 16)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		}
		var iv []byte
		iv = make([]byte, 16)
		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
		} else {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}
		ciph, err := kcipher2.New(iv, key)
		buf := make([]byte, 128*1<<10)
		var n int
		for {
			n, err = os.Stdin.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		os.Exit(0)
	}

	if *crypt != "" && *cph == "salsa20" {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
		} else {
			keyHex = *key
		}
		buf := make([]byte, 128*1<<10)
		n, err := os.Stdin.Read(buf)
		if err != nil && err != io.EOF {
			log.Fatal(err)
		}
		var key = [32]byte{}
		var raw []byte
		if keyHex != "" {
			raw, _ = hex.DecodeString(keyHex)
			copy(key[:], raw)
		} else {
			raw := make([]byte, 32)
			_, err = io.ReadFull(rand.Reader, raw)
			if err != nil {
				log.Fatal(err)
			}
			key = *byte32(raw)
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key[:]))
		}

		var iv []byte
		iv = make([]byte, 24)
		var nonce [24]byte
		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
			copy(nonce[:], iv)
		} else {
			fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
		}
		salsa20.XORKeyStream(buf[:n], buf[:n], nonce[:], &key)

		if _, err := os.Stdout.Write(buf[:n]); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	if *crypt != "" && *cph == "chacha20" {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
		} else {
			keyHex = *key
		}
		buf := make([]byte, 128*1<<10)
		n, err := os.Stdin.Read(buf)
		if err != nil && err != io.EOF {
			log.Fatal(err)
		}
		var key1 []byte
		var raw []byte
		if keyHex != "" {
			raw, _ = hex.DecodeString(keyHex)
			key1 = raw
		} else {
			raw := make([]byte, 32)
			_, err = io.ReadFull(rand.Reader, raw)
			if err != nil {
				log.Fatal(err)
			}
			key1 = raw
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key1))
		}

		var iv []byte
		iv = make([]byte, 24)
		var nonce [24]byte
		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
			copy(nonce[:], iv)
		} else {
			fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
		}
		cypher, _ := chacha20.NewUnauthenticatedCipher(key1, nonce[:])
		cypher.XORKeyStream(buf[:n], buf[:n])

		if _, err := os.Stdout.Write(buf[:n]); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	if *crypt != "" && (*cph == "hc128" || *cph == "hc256" || *cph == "skein") {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
		} else {
			keyHex = *key
		}

		var ciph cipher.Stream
		if *cph == "hc256" {
			var key [32]byte
			if keyHex != "" {
				raw, _ := hex.DecodeString(keyHex)
				key = *byte32(raw)
			} else {
				keyRaw = make([]byte, 32)
				_, err = io.ReadFull(rand.Reader, keyRaw)
				if err != nil {
					log.Fatal(err)
				}
				key = *byte32(keyRaw)
				fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key[:]))
			}
			var nonce [32]byte
			var iv []byte
			iv = make([]byte, 32)
			if *vector != "" {
				iv, _ = hex.DecodeString(*vector)
				copy(nonce[:], iv)
			} else {
				fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
			}
			ciph = hc256.NewCipher(&nonce, &key)
			if len(key) != 32 {
				log.Fatal(err)
			}
		} else if *cph == "hc128" {
			var key [16]byte
			var raw []byte
			if keyHex != "" {
				raw, _ = hex.DecodeString(keyHex)
				key = *byte16(raw)
			} else {
				keyRaw = make([]byte, 16)
				_, err = io.ReadFull(rand.Reader, keyRaw)
				if err != nil {
					log.Fatal(err)
				}
				key = *byte16(keyRaw)
				fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key[:]))
			}
			var iv []byte
			iv = make([]byte, 16)
			var nonce [16]byte
			if *vector != "" {
				iv, _ = hex.DecodeString(*vector)
				copy(nonce[:], iv)
			} else {
				fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
			}
			copy(key[:], raw)
			ciph = hc128.NewCipher(&nonce, &key)
			if len(key) != 16 {
				log.Fatal(err)
			}
		} else if *cph == "skein" {
			var key []byte
			if keyHex != "" {
				key, _ = hex.DecodeString(keyHex)
			} else {
				key = make([]byte, 32)
				_, err = io.ReadFull(rand.Reader, key)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
			}
			var nonce []byte
			nonce = make([]byte, 32)
			if *vector != "" {
				nonce, _ = hex.DecodeString(*vector)
			} else {
				fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
			}
			ciph = skeincipher.NewStream(key, nonce)
		}
		buf := make([]byte, 128*1<<10)
		var n int

		for {
			n, err = os.Stdin.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt != "" && *cph == "trivium" {
		var keyHex string
		var keyRaw []byte
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 10, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else {
			keyHex = *key
		}
		var key = [10]byte{}
		var err error
		if keyHex != "" {
			raw, err := hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			key = *byte10(raw)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != trivium.KeyLength {
				log.Fatal(err)
			}
		} else {
			keyRaw = make([]byte, 10)
			_, err = io.ReadFull(rand.Reader, keyRaw)
			if err != nil {
				log.Fatal(err)
			}
			key = *byte10(keyRaw)
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key[:]))
		}

		var iv = [10]byte{}

		if *vector == "" {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		} else {
			raw, err := hex.DecodeString(*vector)
			if err != nil {
				log.Fatal(err)
			}
			iv = *byte10(raw)
			if err != nil {
				log.Fatal(err)
			}
		}

		var trivium = trivium.NewTrivium(key, iv)
		reader := bufio.NewReader(os.Stdin)
		writer := bufio.NewWriter(os.Stdout)
		defer writer.Flush()

		var b byte
		for b, err = reader.ReadByte(); err == nil; b, err = reader.ReadByte() {
			kb := trivium.NextByte()
			err := writer.WriteByte(b ^ kb)
			if err != nil {
				log.Fatalf("error writing")
			}
		}
		if err != io.EOF {
			log.Fatalf("error reading")
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "Process took:", elapsed)
		}
	}

	if *crypt != "" && *cph == "rabbit" {
		var keyHex string
		var prvRaw []byte
		if *kdf == "pbkdf2" {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, myHash)
			keyHex = hex.EncodeToString(prvRaw)
		} else {
			keyHex = *key
		}
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 16)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 16 {
				log.Fatal(err)
			}
		}
		var nonce []byte
		if *vector != "" {
			nonce, _ = hex.DecodeString(*vector)
		} else {
			nonce = make([]byte, 8)
			fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
		}
		ciph, _ := rabbitio.NewCipher(key, nonce)
		buf := make([]byte, 64*1<<10)
		var n int
		for {
			n, err = os.Stdin.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt == "eea256" || (*crypt != "" && *cph == "zuc256") {
		var keyHex string
		var keyRaw []byte
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else {
			keyHex = *key
		}
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 32)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 32 {
				log.Fatal(err)
			}
		}
		var nonce []byte
		if *vector != "" {
			nonce, _ = hex.DecodeString(*vector)
		} else {
			nonce = make([]byte, 23)
			fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
		}
		ciph, _ := zuc2.NewCipher(key, nonce)
		buf := make([]byte, 64*1<<10)
		var n int
		for {
			n, err = os.Stdin.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt == "eea128" || (*crypt != "" && *cph == "zuc128") {
		var keyHex string
		var keyRaw []byte
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else {
			keyHex = *key
		}
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 16)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 16 {
				log.Fatal(err)
			}
		}
		var nonce []byte
		if *vector != "" {
			nonce, _ = hex.DecodeString(*vector)
		} else {
			nonce = make([]byte, 16)
			fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
		}
		ciph, _ := zuc2.NewCipher(key, nonce)
		buf := make([]byte, 64*1<<10)
		var n int
		for {
			n, err = os.Stdin.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *mac == "eia256" {
		var keyHex string
		var keyRaw []byte
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else {
			keyHex = *key
		}
		var err error
		if keyHex == "" {
			keyRaw, _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(keyRaw))
		} else {
			keyRaw, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(keyRaw) != 32 {
				log.Fatal(err)
			}
		}
		var nonce []byte
		if *vector != "" {
			nonce, err = hex.DecodeString(*vector)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			nonce, _ = hex.DecodeString("0000000000000000000000000000000000000000000000")
			fmt.Fprintln(os.Stderr, "IV=", hex.EncodeToString(nonce))
		}
		h, _ := zuc2.NewHash256(keyRaw, nonce, *length/8)
		if _, err := io.Copy(h, os.Stdin); err != nil {
			log.Fatal(err)
		}
		io.Copy(h, os.Stdin)
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Printf("MAC-%s= %x\n", strings.ToUpper(*mac), h.Sum(nil))
		os.Exit(0)
	}

	if *mac == "eia128" {
		var keyHex string
		var keyRaw []byte
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else {
			keyHex = *key
		}
		var err error
		if keyHex == "" {
			keyRaw, _ = hex.DecodeString("00000000000000000000000000000000")
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(keyRaw))
		} else {
			keyRaw, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(keyRaw) != 16 {
				log.Fatal(err)
			}
		}
		var nonce []byte
		if *vector != "" {
			nonce, err = hex.DecodeString(*vector)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			nonce, _ = hex.DecodeString("00000000000000000000000000000000")
			fmt.Fprintln(os.Stderr, "IV=", hex.EncodeToString(nonce))
		}
		h, _ := zuc2.NewHash(keyRaw, nonce)
		if _, err := io.Copy(h, os.Stdin); err != nil {
			log.Fatal(err)
		}
		io.Copy(h, os.Stdin)
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Printf("MAC-%s= %x\n", strings.ToUpper(*mac), h.Sum(nil))
		os.Exit(0)
	}

	if *crypt != "" && (*cph == "a51") {
		var keyHex string
		var prvRaw []byte
		if *kdf == "pbkdf2" {
			prvRaw = pbkdf2.Key([]byte([]byte(*key)), []byte(*salt), *iter, 32, myHash)
			keyHex = hex.EncodeToString(prvRaw)
		} else {
			keyHex = *key
		}
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 32)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 32 {
				log.Fatal(err)
			}
		}

		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			t := a51.Crypt(s.Text(), key)
			fmt.Println(t)
		}
		if err := s.Err(); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt == "enc" && (*cph == "ascon" || *cph == "grain") {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, 16)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:16])
		} else {
			keyHex = *key
		}
		var key []byte
		if keyHex == "" {
			key = make([]byte, 16)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 16 {
				log.Fatal(err)
			}
		}

		var aead cipher.AEAD
		if *cph == "ascon" {
			aead, err = ascon.New128(key)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "grain" {
			aead, err = grain.New(key)
			if err != nil {
				log.Fatal(err)
			}
		}

		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		msg := buf.Bytes()

		nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())

		out := aead.Seal(nonce, nonce, msg, []byte(*info))
		fmt.Printf("%s", out)

		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt == "dec" && (*cph == "ascon" || *cph == "grain") {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, 16)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:16])
		} else {
			keyHex = *key
		}
		var key []byte
		if keyHex != "" {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 16 {
				log.Fatal(err)
			}
		} else {
			log.Fatal("Null key.")
			os.Exit(2)
		}

		var aead cipher.AEAD
		if *cph == "ascon" {
			aead, err = ascon.New128(key)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "grain" {
			aead, err = grain.New(key)
			if err != nil {
				log.Fatal(err)
			}
		}

		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		msg := buf.Bytes()

		nonce, msg := msg[:aead.NonceSize()], msg[aead.NonceSize():]

		out, err := aead.Open(nil, nonce, msg, []byte(*info))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", out)

		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt != "" && *cph == "shannon" {
		var keyHex string
		var prvRaw []byte
		if *kdf == "pbkdf2" {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, myHash)
			keyHex = hex.EncodeToString(prvRaw)
		} else {
			keyHex = *key
		}
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 32)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 32 {
				log.Fatal(err)
			}
		}

		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		line := buf.Bytes()

		if *crypt == "enc" {
			s := shannon.New(key)
			s.Encrypt(line)
			mac := make([]byte, 16)
			s.Finish(mac)
			fmt.Fprintf(os.Stderr, "MAC= %x\n", mac)
			fmt.Printf("%s", string(line))
			if *util == "chrono" {
				elapsed := time.Since(start)
				fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
			}
			os.Exit(0)
		} else {
			s := shannon.New(key)
			s.Decrypt(line)
			mac, _ := hex.DecodeString(*mac)
			if s.CheckMac([]byte(mac)) == nil && string(mac) != "" {
				fmt.Println("MAC OK")
			} else {
				fmt.Println("MAC Error")
			}
			fmt.Printf("%s", string(line))
			if *util == "chrono" {
				elapsed := time.Since(start)
				fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
			}
			os.Exit(0)
		}
	}

	if *crypt != "" && *cph == "bb4" {
		var keyHex string
		var prvRaw []byte
		if *kdf == "pbkdf2" {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, myHash)
			keyHex = hex.EncodeToString(prvRaw)
		} else {
			keyHex = *key
		}
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 32)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 32 {
				log.Fatal(err)
			}
		}
		var nonce []byte
		if *vector != "" {
			nonce, _ = hex.DecodeString(*vector)
		} else {
			nonce, _ = bb4.GenNonce()
			fmt.Fprintf(os.Stderr, "IV= %x\n", nonce)
		}
		ciph, _ := bb4.NewCipher(key, nonce)
		buf := make([]byte, 64*1<<10)
		var n int
		for {
			n, err = os.Stdin.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			ciph.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt == "eea3" || (*crypt == "uea2" || *cph == "snow3g" && *crypt != "") {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, 16)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:16])
		} else {
			keyHex = *key
		}
		var key []byte
		if keyHex == "" {
			key = make([]byte, 16)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 16 {
				log.Fatal(err)
			}
		}

		ciph1 := eea3.NewEEA3(key, 0x2738cdaa, 0x1a, zuc.KEY_UPLINK)
		ciph2 := uea2.NewUEA2(key, 0x2738cdaa, 0x1a, snow3g.KEY_UPLINK)

		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		msg := buf.Bytes()

		var length uint32
		length = uint32(len(msg))
		var t []byte
		if *crypt == "eea3" {
			t = ciph1.Encrypt(msg, length*8)
		} else if *crypt == "uea2" || *cph == "snow3g" {
			t = ciph2.Encrypt(msg, length*8)
		}
		fmt.Printf("%s", string(t))

		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if (*mac == "eia3" || *mac == "uia2") && *sig == "" {
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		msg := buf.Bytes()

		var keyHex string
		var prvRaw []byte
		if *kdf == "pbkdf2" {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, myHash)
			keyHex = hex.EncodeToString(prvRaw)
		} else {
			keyHex = *key
		}
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 16)
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 16 {
				log.Fatal(err)
			}
		}

		ciph1 := eia3.NewEIA3([]byte(key), 0x2738cdaa, 0x1a, zuc.KEY_UPLINK)
		ciph2 := uia2.NewUIA2([]byte(key), 0x2738cdaa, 0x1a, snow3g.KEY_UPLINK)

		var length1 uint32
		var length2 uint64
		length1 = uint32(len(msg))
		length2 = uint64(len(msg))
		var t []byte
		if *mac == "eia3" {
			t = ciph1.Hash([]byte(msg), length1*8)
		} else {
			t = ciph2.Hash([]byte(msg), length2*8)
		}
		fmt.Printf("MAC-%s= %x\n", strings.ToUpper(*mac), t)
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "Process took:", elapsed)
		}
		os.Exit(0)
	}

	if (*mac == "eia3" || *mac == "uia2") && *sig != "" {
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		msg := buf.Bytes()

		var keyHex string
		var prvRaw []byte
		if *kdf == "pbkdf2" {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 16, myHash)
			keyHex = hex.EncodeToString(prvRaw)
		} else {
			keyHex = *key
		}
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, 16)
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 16 {
				log.Fatal(err)
			}
		}

		ciph1 := eia3.NewEIA3([]byte(key), 0x2738cdaa, 0x1a, zuc.KEY_UPLINK)
		ciph2 := uia2.NewUIA2([]byte(key), 0x2738cdaa, 0x1a, snow3g.KEY_UPLINK)

		var length1 uint32
		var length2 uint64
		length1 = uint32(len(msg))
		length2 = uint64(len(msg))
		var t bool
		h, _ := hex.DecodeString(*sig)
		if *mac == "eia3" {
			t = ciph1.Verify([]byte(msg), length1*8, h)
		} else {
			t = ciph2.Verify([]byte(msg), length2*8, h)
		}
		fmt.Println(t)
		if t == false {
			os.Exit(1)
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "Process took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt == "enc" && (*cph == "chacha20poly1305") {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, 32)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:32])
		} else {
			keyHex = *key
		}
		var key []byte
		if keyHex == "" {
			key = make([]byte, 32)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 32 {
				log.Fatal(err)
			}
		}

		aead, err := chacha20poly1305.New(key)
		if err != nil {
			log.Fatal(err)
		}

		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		msg := buf.Bytes()

		nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())

		out := aead.Seal(nonce, nonce, msg, []byte(*info))
		fmt.Printf("%s", out)

		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt == "dec" && (*cph == "chacha20poly1305") {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 32, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, 32)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:32])
		} else {
			keyHex = *key
		}
		var key []byte
		if keyHex != "" {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 32 {
				log.Fatal(err)
			}
		} else {
			log.Fatal("Null key.")
			os.Exit(2)
		}

		aead, err := chacha20poly1305.New(key)
		if err != nil {
			log.Fatal(err)
		}

		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		msg := buf.Bytes()

		nonce, msg := msg[:aead.NonceSize()], msg[aead.NonceSize():]

		out, err := aead.Open(nil, nonce, msg, []byte(*info))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", out)

		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if (*crypt == "enc" || *crypt == "dec") && (strings.ToUpper(*mode) == "SIV" || strings.ToUpper(*mode) == "SIV-PMAC") {
		var keyHex string
		var prvRaw []byte
		if *kdf == "pbkdf2" {
			prvRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, sha256.New)
			keyHex = hex.EncodeToString(prvRaw)
		} else {
			keyHex = *key
		}
		var key []byte
		var err error
		if keyHex == "" {
			key = make([]byte, *length/8)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != *length/8 {
				log.Fatal(err)
			}
		}

		var aead cipher.AEAD
		if strings.ToUpper(*mode) == "SIV-PMAC" {
			aead, err = miscreant.NewAEAD("AES-PMAC-SIV", key, 16)
		} else {
			aead, err = miscreant.NewAEAD("AES-SIV", key, 16)
		}
		if err != nil {
			log.Fatal(err)
		}

		if *crypt == "enc" {
			buf := bytes.NewBuffer(nil)
			data := os.Stdin
			io.Copy(buf, data)
			msg := buf.Bytes()

			nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())

			out := aead.Seal(nonce, nonce, msg, []byte(*info))
			fmt.Printf("%s", out)

			if *util == "chrono" {
				elapsed := time.Since(start)
				fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
			}
			os.Exit(0)
		} else {
			buf := bytes.NewBuffer(nil)
			data := os.Stdin
			io.Copy(buf, data)
			msg := buf.Bytes()

			nonce, msg := msg[:aead.NonceSize()], msg[aead.NonceSize():]

			out, err := aead.Open(nil, nonce, msg, []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s", out)

			if *util == "chrono" {
				elapsed := time.Since(start)
				fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
			}
			os.Exit(0)
		}
	}

	if *crypt == "enc" && strings.ToUpper(*mode) == "MGM" && (*cph == "aes" || *cph == "anubis" || *cph == "serpent" || *cph == "twofish" || *cph == "camellia" || *cph == "seed" || *cph == "rc6" || *cph == "sm4" || *cph == "kuznechik" || *cph == "grasshopper" || *cph == "lea" || *cph == "blowfish" || *cph == "hight" || *cph == "idea" || *cph == "cast5" || *cph == "rc5" || *cph == "tea" || *cph == "xtea" || *cph == "rtea" || *cph == "xtea" || *cph == "rtea" || *cph == "gost89" || *cph == "magma" || *cph == "3des" || *cph == "skipjack" || *cph == "simon64" || *cph == "speck64" || *cph == "speck128" || *cph == "simon128" || *cph == "aria" || *cph == "present" || *cph == "twine" || *cph == "misty1" || *cph == "seaturtle" || *cph == "sealion") {
		var keyHex string
		var keyRaw []byte
		var err error

		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
		} else {
			keyHex = *key
		}
		var key []byte
		if keyHex == "" {
			if *cph == "sm4" || *cph == "hight" || *cph == "idea" || *cph == "cast5" || *cph == "rc5" || *cph == "tea" || *cph == "xtea" || *cph == "rtea" || *cph == "simon64" || *cph == "speck64" || *cph == "present" || *cph == "twine" || *cph == "misty1" {
				if *length < 128 {
					key = make([]byte, 16)[:*length/8]
				} else {
					key = make([]byte, 16)
				}
			} else if *cph == "skipjack" {
				key = make([]byte, 10)
			} else if *cph == "3des" {
				key = make([]byte, 24)
			} else {
				key = make([]byte, *length/8)
			}
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != *length/8 && len(key) != 10 && len(key) != 12 && len(key) != 16 && len(key) != 24 {
				log.Fatal(err)
			}
		}

		var ciph cipher.Block
		var n int
		if *cph == "camellia" {
			ciph, err = camellia.NewCipher(key)
			n = 16
		} else if *cph == "aes" {
			ciph, err = aes.NewCipher(key)
			n = 16
		} else if *cph == "aria" {
			ciph, err = aria.NewCipher(key)
			n = 16
		} else if *cph == "lea" {
			ciph, err = lea.NewCipher(key)
			n = 16
		} else if *cph == "serpent" {
			ciph, err = serpent.NewCipher(key)
			n = 16
		} else if *cph == "twofish" {
			ciph, err = twofish.NewCipher(key)
			n = 16
		} else if *cph == "seed" {
			ciph, err = seed.NewCipher(key)
			n = 16
		} else if *cph == "sm4" {
			ciph, _ = sm4.NewCipher(key)
			n = 16
		} else if *cph == "rc6" {
			ciph = rc6.NewCipher(key)
			n = 16
		} else if *cph == "kuznechik" {
			ciph = gost3412128.NewCipher(key)
			n = 16
		} else if *cph == "gost89" {
			ciph = gost28147.NewCipher(key, &gost28147.SboxIdGostR341194CryptoProParamSet)
			n = 8
		} else if *cph == "magma" {
			ciph = gost341264.NewCipher(key)
			n = 8
		} else if *cph == "idea" {
			ciph, _ = idea.NewCipher(key)
			n = 8
		} else if *cph == "hight" {
			ciph, _ = hight.NewCipher(key)
			n = 8
		} else if *cph == "cast5" {
			ciph, _ = cast5.NewCipher(key)
			n = 8
		} else if *cph == "tea" {
			ciph, _ = tea.NewCipher(key)
			n = 8
		} else if *cph == "xtea" {
			ciph, _ = xtea.NewCipher(key)
			n = 8
		} else if *cph == "rtea" {
			ciph, _ = rtea.NewCipher(key)
			n = 8
		} else if *cph == "rc5" {
			ciph, _ = rc5.New(key)
			n = 8
		} else if *cph == "blowfish" {
			ciph, _ = blowfish.NewCipher(key)
			n = 8
		} else if *cph == "3des" {
			ciph, _ = des.NewTripleDESCipher(key)
			n = 8
		} else if *cph == "skipjack" {
			ciph, _ = skipjack.New(key[0:10])
			n = 8
		} else if *cph == "speck64" {
			ciph = simonspeck.NewSpeck64(key)
			n = 8
		} else if *cph == "simon64" {
			ciph = simonspeck.NewSimon64(key)
			n = 8
		} else if *cph == "speck128" {
			ciph = simonspeck.NewSpeck128(key)
			n = 16
		} else if *cph == "simon128" {
			ciph = simonspeck.NewSimon128(key)
			n = 16
		} else if *cph == "present" {
			ciph, _ = present.NewCipher(key)
			n = 8
		} else if *cph == "twine" {
			ciph, _ = twine.New(key)
			n = 8
		} else if *cph == "misty1" {
			ciph, _ = misty1.New(key)
			n = 8
		} else if *cph == "sealion" {
			ciph, _ = sealion.NewCipher(key)
			n = 16
		} else if *cph == "seaturtle" {
			ciph, _ = seaturtle.NewCipher(key)
			n = 16
		} else if *cph == "grasshopper" {
			ciph, _ = kuznechik.NewCipher(key)
			n = 16
		} else if *cph == "anubis" {
			ciph = anubis.New(key)
			n = 16
		}
		aead, err := mgm.NewMGM(ciph, n)
		if err != nil {
			log.Fatal(err.Error())
		}

		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		msg := buf.Bytes()

		nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())

		out := aead.Seal(nonce, nonce, msg, []byte(*info))
		fmt.Printf("%s", out)

		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt == "dec" && strings.ToUpper(*mode) == "MGM" && (*cph == "aes" || *cph == "serpent" || *cph == "twofish" || *cph == "camellia" || *cph == "seed" || *cph == "rc6" || *cph == "sm4" || *cph == "kuznechik" || *cph == "grasshopper" || *cph == "lea" || *cph == "hight" || *cph == "idea" || *cph == "cast5" || *cph == "rc5" || *cph == "tea" || *cph == "xtea" || *cph == "rtea" || *cph == "gost89" || *cph == "magma" || *cph == "blowfish" || *cph == "3des" || *cph == "skipjack" || *cph == "speck64" || *cph == "simon64" || *cph == "speck128" || *cph == "simon128" || *cph == "aria" || *cph == "present" || *cph == "twine" || *cph == "misty1" || *cph == "seaturtle" || *cph == "sealion") {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
		} else {
			keyHex = *key
		}
		var key []byte
		if keyHex != "" {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != *length/8 && len(key) != 10 && len(key) != 16 && len(key) != 24 {
				log.Fatal(err)
			}
		} else {
			log.Fatal("Null key.")
		}

		var ciph cipher.Block
		var n int
		if *cph == "camellia" {
			ciph, err = camellia.NewCipher(key)
			n = 16
		} else if *cph == "aes" {
			ciph, err = aes.NewCipher(key)
			n = 16
		} else if *cph == "aria" {
			ciph, err = aria.NewCipher(key)
			n = 16
		} else if *cph == "lea" {
			ciph, err = lea.NewCipher(key)
			n = 16
		} else if *cph == "serpent" {
			ciph, err = serpent.NewCipher(key)
			n = 16
		} else if *cph == "twofish" {
			ciph, err = twofish.NewCipher(key)
			n = 16
		} else if *cph == "seed" {
			ciph, err = seed.NewCipher(key)
			n = 16
		} else if *cph == "sm4" {
			ciph, _ = sm4.NewCipher(key)
			n = 16
		} else if *cph == "rc6" {
			ciph = rc6.NewCipher(key)
			n = 16
		} else if *cph == "kuznechik" {
			ciph = gost3412128.NewCipher(key)
			n = 16
		} else if *cph == "magma" {
			ciph = gost341264.NewCipher(key)
			n = 8
		} else if *cph == "gost89" {
			ciph = gost28147.NewCipher(key, &gost28147.SboxIdGostR341194CryptoProParamSet)
			n = 8
		} else if *cph == "idea" {
			ciph, _ = idea.NewCipher(key)
			n = 8
		} else if *cph == "hight" {
			ciph, _ = hight.NewCipher(key)
			n = 8
		} else if *cph == "cast5" {
			ciph, _ = cast5.NewCipher(key)
			n = 8
		} else if *cph == "tea" {
			ciph, _ = tea.NewCipher(key)
			n = 8
		} else if *cph == "xtea" {
			ciph, _ = xtea.NewCipher(key)
			n = 8
		} else if *cph == "rtea" {
			ciph, _ = rtea.NewCipher(key)
			n = 8
		} else if *cph == "rc5" {
			ciph, _ = rc5.New(key)
			n = 8
		} else if *cph == "blowfish" {
			ciph, _ = blowfish.NewCipher(key)
			n = 8
		} else if *cph == "3des" {
			ciph, _ = des.NewTripleDESCipher(key)
			n = 8
		} else if *cph == "skipjack" {
			ciph, _ = skipjack.New(key[0:10])
			n = 8
		} else if *cph == "speck64" {
			ciph = simonspeck.NewSpeck64(key)
			n = 8
		} else if *cph == "simon64" {
			ciph = simonspeck.NewSimon64(key)
			n = 8
		} else if *cph == "speck128" {
			ciph = simonspeck.NewSpeck128(key)
			n = 16
		} else if *cph == "simon128" {
			ciph = simonspeck.NewSimon128(key)
			n = 16
		} else if *cph == "present" {
			ciph, _ = present.NewCipher(key)
			n = 8
		} else if *cph == "twine" {
			ciph, _ = twine.New(key)
			n = 8
		} else if *cph == "misty1" {
			ciph, _ = misty1.New(key)
			n = 8
		} else if *cph == "sealion" {
			ciph, _ = sealion.NewCipher(key)
			n = 16
		} else if *cph == "seaturtle" {
			ciph, _ = seaturtle.NewCipher(key)
			n = 16
		} else if *cph == "grasshopper" {
			ciph, _ = kuznechik.NewCipher(key)
			n = 16
		} else if *cph == "anubis" {
			ciph = anubis.New(key)
			n = 16
		}
		aead, err := mgm.NewMGM(ciph, n)
		if err != nil {
			log.Fatal(err.Error())
		}

		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		msg := buf.Bytes()

		nonce, msg := msg[:aead.NonceSize()], msg[aead.NonceSize():]

		out, err := aead.Open(nil, nonce, msg, []byte(*info))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", out)

		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt == "enc" && strings.ToUpper(*mode) == "CFB8" && (*cph == "blowfish" || *cph == "hight" || *cph == "3des" || *cph == "idea" || *cph == "cast5" || *cph == "rc5" || *cph == "tea" || *cph == "xtea" || *cph == "rtea" || *cph == "skipjack" || *cph == "speck64" || *cph == "simon64" || *cph == "present" || *cph == "twine" || *cph == "misty1" || *cph == "magma" || *cph == "gost89" || *cph == "simon32" || *cph == "speck32") && (*mode != "GCM" && *mode != "MGM" && *mode != "EAX" && *mode != "OCB" && *mode != "CCM") {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)[:*length/8]
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
		} else {
			keyHex = *key
		}
		var key []byte
		if keyHex == "" {
			if *cph == "magma" || *cph == "gost89" {
				key = make([]byte, 32)
			} else if *cph == "skipjack" {
				key = make([]byte, 10)
			} else if *cph == "3des" {
				key = make([]byte, 24)
			} else if *cph == "blowfish" {
				key = make([]byte, *length/8)
			} else {
				if *length < 128 {
					key = make([]byte, *length/8)
				} else {
					key = make([]byte, 16)
				}
			}
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 32 && len(key) != 8 && len(key) != 16 && len(key) != 12 && len(key) != 10 && len(key) != 24 {
				log.Fatal(err)
			}
		}
		var ciph cipher.Block
		var iv []byte
		if *cph == "blowfish" {
			ciph, err = blowfish.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "idea" {
			ciph, _ = idea.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "hight" {
			ciph, _ = hight.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "cast5" {
			ciph, _ = cast5.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "tea" {
			ciph, _ = tea.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "xtea" {
			ciph, _ = xtea.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "rtea" {
			ciph, _ = rtea.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "rc5" {
			ciph, _ = rc5.New(key)
			iv = make([]byte, 8)
		} else if *cph == "skipjack" {
			ciph, _ = skipjack.New(key)
			iv = make([]byte, 8)
		} else if *cph == "speck64" {
			ciph = simonspeck.NewSpeck64(key)
			iv = make([]byte, 8)
		} else if *cph == "simon64" {
			ciph = simonspeck.NewSimon64(key)
			iv = make([]byte, 8)
		} else if *cph == "present" {
			ciph, _ = present.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "twine" {
			ciph, _ = twine.New(key)
			iv = make([]byte, 8)
		} else if *cph == "misty1" {
			ciph, _ = misty1.New(key)
			iv = make([]byte, 8)
		} else if *cph == "3des" {
			ciph, _ = des.NewTripleDESCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "magma" {
			ciph = gost341264.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "gost89" {
			ciph = gost28147.NewCipher(key, &gost28147.SboxIdGostR341194CryptoProParamSet)
			iv = make([]byte, 8)
		} else if *cph == "simon32" {
			ciph = simonspeck.NewSimon32(key)
			iv = make([]byte, 4)
		} else if *cph == "speck32" {
			ciph = simonspeck.NewSpeck32(key)
			iv = make([]byte, 4)
		}
		if err != nil {
			log.Fatal(err)
		}

		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
		} else {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}

		stream := CFB8.NewCFB8Encrypt(ciph, iv)

		buf := make([]byte, 128*1<<10)
		var n int
		for {
			n, err = os.Stdin.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			stream.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt == "dec" && strings.ToUpper(*mode) == "CFB8" && (*cph == "blowfish" || *cph == "hight" || *cph == "3des" || *cph == "idea" || *cph == "cast5" || *cph == "rc5" || *cph == "tea" || *cph == "xtea" || *cph == "rtea" || *cph == "skipjack" || *cph == "speck64" || *cph == "simon64" || *cph == "present" || *cph == "twine" || *cph == "misty1" || *cph == "magma" || *cph == "gost89" || *cph == "simon32" || *cph == "speck32") && (*mode != "GCM" && *mode != "MGM" && *mode != "EAX" && *mode != "OCB" && *mode != "CCM") {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)[:*length/8]
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
		} else {
			keyHex = *key
		}
		var key []byte
		if keyHex == "" {
			if *cph == "magma" || *cph == "gost89" {
				key = make([]byte, 32)
			} else if *cph == "skipjack" {
				key = make([]byte, 10)
			} else if *cph == "3des" {
				key = make([]byte, 24)
			} else if *cph == "blofish" {
				key = make([]byte, *length/8)
			} else {
				if *length < 128 {
					key = make([]byte, *length/8)
				} else {
					key = make([]byte, 16)
				}
			}
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 32 && len(key) != 8 && len(key) != 16 && len(key) != 12 && len(key) != 10 && len(key) != 24 {
				log.Fatal(err)
			}
		}
		var ciph cipher.Block
		var iv []byte
		if *cph == "blowfish" {
			ciph, err = blowfish.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "idea" {
			ciph, _ = idea.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "hight" {
			ciph, _ = hight.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "cast5" {
			ciph, _ = cast5.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "tea" {
			ciph, _ = tea.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "xtea" {
			ciph, _ = xtea.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "rtea" {
			ciph, _ = rtea.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "rc5" {
			ciph, _ = rc5.New(key)
			iv = make([]byte, 8)
		} else if *cph == "sm4" {
			ciph, _ = sm4.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "seed" {
			ciph, _ = seed.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "skipjack" {
			ciph, _ = skipjack.New(key)
			iv = make([]byte, 8)
		} else if *cph == "speck64" {
			ciph = simonspeck.NewSpeck64(key)
			iv = make([]byte, 8)
		} else if *cph == "simon64" {
			ciph = simonspeck.NewSimon64(key)
			iv = make([]byte, 8)
		} else if *cph == "present" {
			ciph, _ = present.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "twine" {
			ciph, _ = twine.New(key)
			iv = make([]byte, 8)
		} else if *cph == "misty1" {
			ciph, _ = misty1.New(key)
			iv = make([]byte, 8)
		} else if *cph == "3des" {
			ciph, _ = des.NewTripleDESCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "magma" {
			ciph = gost341264.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "gost89" {
			ciph = gost28147.NewCipher(key, &gost28147.SboxIdGostR341194CryptoProParamSet)
			iv = make([]byte, 8)
		} else if *cph == "simon32" {
			ciph = simonspeck.NewSimon32(key)
			iv = make([]byte, 4)
		} else if *cph == "speck32" {
			ciph = simonspeck.NewSpeck32(key)
			iv = make([]byte, 4)
		}
		if err != nil {
			log.Fatal(err)
		}

		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
		} else {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}

		stream := CFB8.NewCFB8Decrypt(ciph, iv)

		buf := make([]byte, 128*1<<10)
		var n int
		for {
			n, err = os.Stdin.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			stream.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt == "enc" && strings.ToUpper(*mode) == "CFB8" && (*cph == "aes" || *cph == "anubis" || *cph == "serpent" || *cph == "twofish" || *cph == "camellia" || *cph == "seed" || *cph == "rc6" || *cph == "sm4" || *cph == "kuznechik" || *cph == "grasshopper" || *cph == "lea" || *cph == "speck128" || *cph == "simon128" || *cph == "aria" || *cph == "seaturtle" || *cph == "sealion" || *cph == "threefish" || *cph == "threefish256" || *cph == "threefish512" || *cph == "threefish1024") {
		var keyHex string
		var keyRaw []byte
		var err error

		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
		} else {
			keyHex = *key
		}
		var key []byte
		if keyHex == "" {
			if *cph == "sm4" {
				if *length < 128 {
					key = make([]byte, 16)[:*length/8]
				} else {
					key = make([]byte, 16)
				}
			} else if *cph == "skipjack" {
				key = make([]byte, 10)
			} else if *cph == "3des" {
				key = make([]byte, 24)
			} else {
				key = make([]byte, *length/8)
			}
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != *length/8 && len(key) != 10 && len(key) != 12 && len(key) != 16 && len(key) != 24 {
				log.Fatal(err)
			}
		}

		var ciph cipher.Block
		var iv []byte
		if *cph == "sm4" {
			ciph, _ = sm4.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "seed" {
			ciph, _ = seed.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "camellia" {
			ciph, err = camellia.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "aes" {
			ciph, err = aes.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "aria" {
			ciph, err = aria.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "lea" {
			ciph, err = lea.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "serpent" {
			ciph, err = serpent.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "twofish" {
			ciph, err = twofish.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "seed" {
			ciph, err = seed.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "rc6" {
			ciph = rc6.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "threefish256" || *cph == "threefish" {
			tweak := make([]byte, 16)
			iv = make([]byte, 32)
			ciph, err = threefish.New256(key, tweak)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "threefish512" {
			tweak := make([]byte, 16)
			iv = make([]byte, 64)
			ciph, err = threefish.New512(key, tweak)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "threefish1024" {
			tweak := make([]byte, 16)
			iv = make([]byte, 128)
			ciph, err = threefish.New1024(key, tweak)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "kuznechik" {
			ciph = gost3412128.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "speck128" {
			ciph = simonspeck.NewSpeck128(key)
			iv = make([]byte, 16)
		} else if *cph == "simon128" {
			ciph = simonspeck.NewSimon128(key)
			iv = make([]byte, 16)
		} else if *cph == "sealion" {
			ciph, _ = sealion.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "seaturtle" {
			ciph, _ = seaturtle.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "grasshopper" {
			ciph, _ = kuznechik.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "anubis" {
			ciph = anubis.New(key)
			iv = make([]byte, 16)
		}
		if err != nil {
			log.Fatal(err)
		}
		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
		} else {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}
		stream := CFB8.NewCFB8Encrypt(ciph, iv)

		buf := make([]byte, 128*1<<10)
		var n int
		for {
			n, err = os.Stdin.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			stream.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt == "dec" && strings.ToUpper(*mode) == "CFB8" && (*cph == "aes" || *cph == "anubis" || *cph == "serpent" || *cph == "twofish" || *cph == "camellia" || *cph == "seed" || *cph == "rc6" || *cph == "sm4" || *cph == "kuznechik" || *cph == "grasshopper" || *cph == "lea" || *cph == "speck128" || *cph == "simon128" || *cph == "aria" || *cph == "seaturtle" || *cph == "sealion" || *cph == "threefish" || *cph == "threefish256" || *cph == "threefish512" || *cph == "threefish1024") {
		var keyHex string
		var keyRaw []byte
		var err error

		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
		} else {
			keyHex = *key
		}
		var key []byte
		if keyHex == "" {
			if *cph == "sm4" || *cph == "hight" || *cph == "idea" || *cph == "cast5" || *cph == "rc5" || *cph == "tea" || *cph == "xtea" || *cph == "rtea" || *cph == "simon64" || *cph == "speck64" || *cph == "present" || *cph == "twine" || *cph == "misty1" {
				if *length < 128 {
					key = make([]byte, 16)[:*length/8]
				} else {
					key = make([]byte, 16)
				}
			} else if *cph == "skipjack" {
				key = make([]byte, 10)
			} else if *cph == "3des" {
				key = make([]byte, 24)
			} else {
				key = make([]byte, *length/8)
			}
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != *length/8 && len(key) != 10 && len(key) != 12 && len(key) != 16 && len(key) != 24 {
				log.Fatal(err)
			}
		}

		var ciph cipher.Block
		var iv []byte
		if *cph == "sm4" {
			ciph, _ = sm4.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "seed" {
			ciph, _ = seed.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "camellia" {
			ciph, err = camellia.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "aes" {
			ciph, err = aes.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "aria" {
			ciph, err = aria.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "lea" {
			ciph, err = lea.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "serpent" {
			ciph, err = serpent.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "twofish" {
			ciph, err = twofish.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "seed" {
			ciph, err = seed.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "rc6" {
			ciph = rc6.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "threefish256" || *cph == "threefish" {
			tweak := make([]byte, 16)
			iv = make([]byte, 32)
			ciph, err = threefish.New256(key, tweak)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "threefish512" {
			tweak := make([]byte, 16)
			iv = make([]byte, 64)
			ciph, err = threefish.New512(key, tweak)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "threefish1024" {
			tweak := make([]byte, 16)
			iv = make([]byte, 128)
			ciph, err = threefish.New1024(key, tweak)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "kuznechik" {
			ciph = gost3412128.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "speck128" {
			ciph = simonspeck.NewSpeck128(key)
			iv = make([]byte, 16)
		} else if *cph == "simon128" {
			ciph = simonspeck.NewSimon128(key)
			iv = make([]byte, 16)
		} else if *cph == "sealion" {
			ciph, _ = sealion.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "seaturtle" {
			ciph, _ = seaturtle.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "grasshopper" {
			ciph, _ = kuznechik.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "anubis" {
			ciph = anubis.New(key)
			iv = make([]byte, 16)
		}
		if err != nil {
			log.Fatal(err)
		}
		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
		} else {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}
		stream := CFB8.NewCFB8Decrypt(ciph, iv)
		buf := make([]byte, 128*1<<10)
		var n int
		for {
			n, err = os.Stdin.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			stream.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if (*crypt == "enc" || *crypt == "dec") && strings.ToUpper(*mode) == "IGE" && (*cph == "aes" || *cph == "serpent" || *cph == "twofish" || *cph == "camellia" || *cph == "seed" || *cph == "rc6" || *cph == "sm4" || *cph == "kuznechik" || *cph == "grasshopper" || *cph == "lea" || *cph == "speck128" || *cph == "simon128" || *cph == "aria" || *cph == "seaturtle" || *cph == "sealion" || *cph == "threefish" || *cph == "threefish256" || *cph == "threefish512" || *cph == "threefish1024" || *cph == "blowfish" || *cph == "hight" || *cph == "3des" || *cph == "idea" || *cph == "cast5" || *cph == "rc5" || *cph == "tea" || *cph == "xtea" || *cph == "rtea" || *cph == "skipjack" || *cph == "speck64" || *cph == "simon64" || *cph == "present" || *cph == "twine" || *cph == "misty1" || *cph == "magma" || *cph == "gost89" || *cph == "simon32" || *cph == "speck32") {
		var keyHex string
		var keyRaw []byte
		var err error

		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
		} else {
			keyHex = *key
		}
		var key []byte
		if keyHex == "" {
			if *cph == "sm4" {
				if *length < 128 {
					key = make([]byte, 16)[:*length/8]
				} else {
					key = make([]byte, 16)
				}
			} else if *cph == "skipjack" {
				key = make([]byte, 10)
			} else if *cph == "3des" {
				key = make([]byte, 24)
			} else {
				key = make([]byte, *length/8)
			}
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != *length/8 && len(key) != 10 && len(key) != 12 && len(key) != 16 && len(key) != 24 {
				log.Fatal(err)
			}
		}

		var ciph cipher.Block
		var iv []byte
		if *cph == "sm4" {
			ciph, _ = sm4.NewCipher(key)
			iv = make([]byte, 32)
		} else if *cph == "seed" {
			ciph, _ = seed.NewCipher(key)
			iv = make([]byte, 32)
		} else if *cph == "camellia" {
			ciph, err = camellia.NewCipher(key)
			iv = make([]byte, 32)
		} else if *cph == "aes" {
			ciph, err = aes.NewCipher(key)
			iv = make([]byte, 32)
		} else if *cph == "aria" {
			ciph, err = aria.NewCipher(key)
			iv = make([]byte, 32)
		} else if *cph == "lea" {
			ciph, err = lea.NewCipher(key)
			iv = make([]byte, 32)
		} else if *cph == "serpent" {
			ciph, err = serpent.NewCipher(key)
			iv = make([]byte, 32)
		} else if *cph == "twofish" {
			ciph, err = twofish.NewCipher(key)
			iv = make([]byte, 32)
		} else if *cph == "seed" {
			ciph, err = seed.NewCipher(key)
			iv = make([]byte, 32)
		} else if *cph == "rc6" {
			ciph = rc6.NewCipher(key)
			iv = make([]byte, 32)
		} else if *cph == "threefish256" || *cph == "threefish" {
			tweak := make([]byte, 16)
			iv = make([]byte, 64)
			ciph, err = threefish.New256(key, tweak)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "threefish512" {
			tweak := make([]byte, 16)
			iv = make([]byte, 128)
			ciph, err = threefish.New512(key, tweak)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "threefish1024" {
			tweak := make([]byte, 16)
			iv = make([]byte, 256)
			ciph, err = threefish.New1024(key, tweak)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "kuznechik" {
			ciph = gost3412128.NewCipher(key)
			iv = make([]byte, 32)
		} else if *cph == "speck128" {
			ciph = simonspeck.NewSpeck128(key)
			iv = make([]byte, 32)
		} else if *cph == "simon128" {
			ciph = simonspeck.NewSimon128(key)
			iv = make([]byte, 32)
		} else if *cph == "sealion" {
			ciph, _ = sealion.NewCipher(key)
			iv = make([]byte, 32)
		} else if *cph == "seaturtle" {
			ciph, _ = seaturtle.NewCipher(key)
			iv = make([]byte, 32)
		} else if *cph == "grasshopper" {
			ciph, _ = kuznechik.NewCipher(key)
			iv = make([]byte, 32)
		} else if *cph == "blowfish" {
			ciph, err = blowfish.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "idea" {
			ciph, _ = idea.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "hight" {
			ciph, _ = hight.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "cast5" {
			ciph, _ = cast5.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "tea" {
			ciph, _ = tea.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "xtea" {
			ciph, _ = xtea.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "rtea" {
			ciph, _ = rtea.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "rc5" {
			ciph, _ = rc5.New(key)
			iv = make([]byte, 16)
		} else if *cph == "skipjack" {
			ciph, _ = skipjack.New(key)
			iv = make([]byte, 16)
		} else if *cph == "speck64" {
			ciph = simonspeck.NewSpeck64(key)
			iv = make([]byte, 16)
		} else if *cph == "simon64" {
			ciph = simonspeck.NewSimon64(key)
			iv = make([]byte, 16)
		} else if *cph == "present" {
			ciph, _ = present.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "twine" {
			ciph, _ = twine.New(key)
			iv = make([]byte, 16)
		} else if *cph == "misty1" {
			ciph, _ = misty1.New(key)
			iv = make([]byte, 16)
		} else if *cph == "3des" {
			ciph, _ = des.NewTripleDESCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "magma" {
			ciph = gost341264.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "gost89" {
			ciph = gost28147.NewCipher(key, &gost28147.SboxIdGostR341194CryptoProParamSet)
			iv = make([]byte, 16)
		} else if *cph == "speck32" {
			ciph = simonspeck.NewSpeck32(key)
			iv = make([]byte, 8)
		} else if *cph == "simon32" {
			ciph = simonspeck.NewSimon32(key)
			iv = make([]byte, 8)
		}
		if err != nil {
			log.Fatal(err)
		}
		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
		} else {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}

		var stream cipher.BlockMode
		if *crypt == "dec" {
			stream = ige.NewIGEDecrypter(ciph, iv)
		} else if *crypt == "enc" {
			stream = ige.NewIGEEncrypter(ciph, iv)
		}

		buf := make([]byte, 24*1<<10)
		var n int
		for {
			n, err = os.Stdin.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			stream.CryptBlocks(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt == "enc" && (*cph == "aes" || *cph == "anubis" || *cph == "serpent" || *cph == "twofish" || *cph == "camellia" || *cph == "seed" || *cph == "rc6" || *cph == "sm4" || *cph == "kuznechik" || *cph == "grasshopper" || *cph == "lea" || *cph == "speck128" || *cph == "simon128" || *cph == "aria" || *cph == "seaturtle" || *cph == "sealion") && (strings.ToUpper(*mode) == "GCM" || strings.ToUpper(*mode) == "CCM" || strings.ToUpper(*mode) == "OCB" || strings.ToUpper(*mode) == "EAX") {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
		} else {
			keyHex = *key
		}
		var key []byte
		if keyHex == "" {
			if *cph == "sm4" {
				key = make([]byte, 16)
			} else {
				key = make([]byte, *length/8)
			}
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != *length/8 && len(key) != 16 && len(key) != 32 {
				log.Fatal(err)
			}
		}

		var ciph cipher.Block
		if *cph == "camellia" {
			ciph, err = camellia.NewCipher(key)
		} else if *cph == "aes" {
			ciph, err = aes.NewCipher(key)
		} else if *cph == "aria" {
			ciph, err = aria.NewCipher(key)
		} else if *cph == "lea" {
			ciph, err = lea.NewCipher(key)
		} else if *cph == "serpent" {
			ciph, err = serpent.NewCipher(key)
		} else if *cph == "twofish" {
			ciph, err = twofish.NewCipher(key)
		} else if *cph == "seed" {
			ciph, err = seed.NewCipher(key)
		} else if *cph == "sm4" {
			ciph, _ = sm4.NewCipher(key[0:16])
		} else if *cph == "rc6" {
			ciph = rc6.NewCipher(key)
		} else if *cph == "kuznechik" {
			ciph = gost3412128.NewCipher(key)
		} else if *cph == "speck128" {
			ciph = simonspeck.NewSpeck128(key)
		} else if *cph == "simon128" {
			ciph = simonspeck.NewSimon128(key)
		} else if *cph == "sealion" {
			ciph, _ = sealion.NewCipher(key)
		} else if *cph == "seaturtle" {
			ciph, _ = seaturtle.NewCipher(key)
		} else if *cph == "grasshopper" {
			ciph, _ = kuznechik.NewCipher(key)
		} else if *cph == "anubis" {
			ciph = anubis.New(key)
		}
		var aead cipher.AEAD
		if strings.ToUpper(*mode) == "GCM" {
			aead, err = cipher.NewGCMWithNonceSize(ciph, 16)
		} else if strings.ToUpper(*mode) == "OCB" {
			aead, err = ocb.NewOCB(ciph)
		} else if strings.ToUpper(*mode) == "EAX" {
			aead, err = eax.NewEAX(ciph)
		} else if strings.ToUpper(*mode) == "CCM" {
			aead, err = ccm.NewCCM(ciph, 16, 13)
		}
		if err != nil {
			log.Fatal(err.Error())
		}

		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		msg := buf.Bytes()

		nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())

		out := aead.Seal(nonce, nonce, msg, []byte(*info))
		fmt.Printf("%s", out)

		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt == "dec" && (*cph == "aes" || *cph == "anubis" || *cph == "serpent" || *cph == "twofish" || *cph == "camellia" || *cph == "seed" || *cph == "rc6" || *cph == "sm4" || *cph == "kuznechik" || *cph == "grasshopper" || *cph == "lea" || *cph == "speck128" || *cph == "simon128" || *cph == "aria" || *cph == "seaturtle" || *cph == "sealion") && (strings.ToUpper(*mode) == "GCM" || strings.ToUpper(*mode) == "CCM" || strings.ToUpper(*mode) == "OCB" || strings.ToUpper(*mode) == "EAX") {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
		} else {
			keyHex = *key
		}
		var key []byte
		if keyHex != "" {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != *length/8 && len(key) != 16 && len(key) != 32 {
				log.Fatal(err)
			}
		} else {
			log.Fatal("Null key.")
			os.Exit(2)
		}

		var ciph cipher.Block
		if *cph == "camellia" {
			ciph, err = camellia.NewCipher(key)
		} else if *cph == "aes" {
			ciph, err = aes.NewCipher(key)
		} else if *cph == "aria" {
			ciph, err = aria.NewCipher(key)
		} else if *cph == "lea" {
			ciph, err = lea.NewCipher(key)
		} else if *cph == "serpent" {
			ciph, err = serpent.NewCipher(key)
		} else if *cph == "twofish" {
			ciph, err = twofish.NewCipher(key)
		} else if *cph == "seed" {
			ciph, err = seed.NewCipher(key)
		} else if *cph == "sm4" {
			ciph, _ = sm4.NewCipher(key[0:16])
		} else if *cph == "rc6" {
			ciph = rc6.NewCipher(key)
		} else if *cph == "kuznechik" {
			ciph = gost3412128.NewCipher(key)
		} else if *cph == "speck128" {
			ciph = simonspeck.NewSpeck128(key)
		} else if *cph == "simon128" {
			ciph = simonspeck.NewSimon128(key)
		} else if *cph == "sealion" {
			ciph, _ = sealion.NewCipher(key)
		} else if *cph == "seaturtle" {
			ciph, _ = seaturtle.NewCipher(key)
		} else if *cph == "grasshopper" {
			ciph, _ = kuznechik.NewCipher(key)
		} else if *cph == "anubis" {
			ciph = anubis.New(key)
		}
		var aead cipher.AEAD
		if strings.ToUpper(*mode) == "GCM" {
			aead, err = cipher.NewGCMWithNonceSize(ciph, 16)
		} else if strings.ToUpper(*mode) == "OCB" {
			aead, err = ocb.NewOCB(ciph)
		} else if strings.ToUpper(*mode) == "EAX" {
			aead, err = eax.NewEAX(ciph)
		} else if strings.ToUpper(*mode) == "CCM" {
			aead, err = ccm.NewCCM(ciph, 16, 13)
		}
		if err != nil {
			log.Fatal(err.Error())
		}

		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		msg := buf.Bytes()

		nonce, msg := msg[:aead.NonceSize()], msg[aead.NonceSize():]

		out, err := aead.Open(nil, nonce, msg, []byte(*info))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", out)

		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt != "" && (strings.ToUpper(*mode) == "CTR" || strings.ToUpper(*mode) == "CNT" || strings.ToUpper(*mode) == "OFB") && (*cph == "aes" || *cph == "anubis" || *cph == "serpent" || *cph == "twofish" || *cph == "camellia" || *cph == "seed" || *cph == "rc6" || *cph == "threefish" || *cph == "threefish256" || *cph == "threefish512" || *cph == "threefish1024" || *cph == "gost89" || *cph == "kuznechik" || *cph == "grasshopper" || *cph == "magma" || *cph == "blowfish" || *cph == "lea" || *cph == "3des" || *cph == "speck128" || *cph == "simon128" || *cph == "aria" || *cph == "seaturtle" || *cph == "sealion") && (*mode != "GCM" && *mode != "MGM") {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
		} else {
			keyHex = *key
		}
		var key []byte
		if keyHex == "" {
			if *cph == "3des" {
				key = make([]byte, 24)
			} else {
				key = make([]byte, *length/8)
			}
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 128 && len(key) != 64 && len(key) != 32 && len(key) != 24 && len(key) != 16 && len(key) != 10 {
				log.Fatal(err)
			}
		}
		var ciph cipher.Block
		var iv []byte
		if *cph == "blowfish" {
			ciph, err = blowfish.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "camellia" {
			ciph, err = camellia.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "aes" {
			ciph, err = aes.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "aria" {
			ciph, err = aria.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "lea" {
			ciph, err = lea.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "serpent" {
			ciph, err = serpent.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "twofish" {
			ciph, err = twofish.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "seed" {
			ciph, err = seed.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "rc6" {
			ciph = rc6.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "threefish256" || *cph == "threefish" {
			tweak := make([]byte, 16)
			iv = make([]byte, 32)
			ciph, err = threefish.New256(key, tweak)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "threefish512" {
			tweak := make([]byte, 16)
			iv = make([]byte, 64)
			ciph, err = threefish.New512(key, tweak)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "threefish1024" {
			tweak := make([]byte, 16)
			iv = make([]byte, 128)
			ciph, err = threefish.New1024(key, tweak)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "gost89" {
			ciph = gost28147.NewCipher(key, &gost28147.SboxIdGostR341194CryptoProParamSet)
			iv = make([]byte, 8)
		} else if *cph == "magma" {
			ciph = gost341264.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "kuznechik" {
			ciph = gost3412128.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "3des" {
			ciph, _ = des.NewTripleDESCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "speck128" {
			ciph = simonspeck.NewSpeck128(key)
			iv = make([]byte, 16)
		} else if *cph == "simon128" {
			ciph = simonspeck.NewSimon128(key)
			iv = make([]byte, 16)
		} else if *cph == "sealion" {
			ciph, _ = sealion.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "seaturtle" {
			ciph, _ = seaturtle.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "grasshopper" {
			ciph, _ = kuznechik.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "anubis" {
			ciph = anubis.New(key)
			iv = make([]byte, 16)
		}
		if err != nil {
			log.Fatal(err)
		}
		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
		} else {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}

		var stream cipher.Stream
		if strings.ToUpper(*mode) == "CTR" || strings.ToUpper(*mode) == "CNT" {
			stream = cipher.NewCTR(ciph, iv)
		} else if strings.ToUpper(*mode) == "OFB" {
			stream = cipher.NewOFB(ciph, iv)
		}
		buf := make([]byte, 128*1<<10)
		var n int
		for {
			n, err = os.Stdin.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			stream.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt != "" && (strings.ToUpper(*mode) == "CTR" || strings.ToUpper(*mode) == "CNT" || strings.ToUpper(*mode) == "OFB") && (*cph == "hight" || *cph == "idea" || *cph == "cast5" || *cph == "rc5" || *cph == "tea" || *cph == "xtea" || *cph == "rtea" || *cph == "seed" || *cph == "sm4" || *cph == "skipjack" || *cph == "speck64" || *cph == "simon64" || *cph == "present" || *cph == "twine" || *cph == "misty1") && (*mode != "GCM" && *mode != "MGM" && *mode != "EAX" && *mode != "OCB" && *mode != "CCM") {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
		} else {
			keyHex = *key
		}
		var key []byte
		if keyHex == "" {
			if *cph == "skipjack" {
				key = make([]byte, 10)
			} else if *cph == "3des" {
				key = make([]byte, 24)
			} else {
				if *length < 128 {
					key = make([]byte, *length/8)
				} else {
					key = make([]byte, 16)
				}
			}
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 16 && len(key) != 12 && len(key) != 10 && len(key) != 24 {
				log.Fatal(err)
			}
		}
		var ciph cipher.Block
		var iv []byte
		if *cph == "idea" {
			ciph, _ = idea.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "hight" {
			ciph, _ = hight.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "cast5" {
			ciph, _ = cast5.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "tea" {
			ciph, _ = tea.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "xtea" {
			ciph, _ = xtea.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "rtea" {
			ciph, _ = rtea.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "rc5" {
			ciph, _ = rc5.New(key)
			iv = make([]byte, 8)
		} else if *cph == "sm4" {
			ciph, _ = sm4.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "seed" {
			ciph, _ = seed.NewCipher(key)
			iv = make([]byte, 16)
		} else if *cph == "skipjack" {
			ciph, _ = skipjack.New(key)
			iv = make([]byte, 8)
		} else if *cph == "speck64" {
			ciph = simonspeck.NewSpeck64(key)
			iv = make([]byte, 8)
		} else if *cph == "simon64" {
			ciph = simonspeck.NewSimon64(key)
			iv = make([]byte, 8)
		} else if *cph == "present" {
			ciph, _ = present.NewCipher(key)
			iv = make([]byte, 8)
		} else if *cph == "twine" {
			ciph, _ = twine.New(key)
			iv = make([]byte, 8)
		} else if *cph == "misty1" {
			ciph, _ = misty1.New(key)
			iv = make([]byte, 8)
		}
		if err != nil {
			log.Fatal(err)
		}
		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
		} else {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		}

		var stream cipher.Stream
		if strings.ToUpper(*mode) == "CTR" || strings.ToUpper(*mode) == "CNT" {
			stream = cipher.NewCTR(ciph, iv)
		} else if strings.ToUpper(*mode) == "OFB" {
			stream = cipher.NewOFB(ciph, iv)
		}
		buf := make([]byte, 128*1<<10)
		var n int
		for {
			n, err = os.Stdin.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			stream.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}

			if err == io.EOF {
				break
			}
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt != "" && (*cph == "speck32" || *cph == "simon32") {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, 8, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, 8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:8])
		} else {
			keyHex = *key
		}
		var key []byte
		if keyHex == "" {
			key = make([]byte, 8)
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "Key=", hex.EncodeToString(key))
		} else {
			key, err = hex.DecodeString(keyHex)
			if err != nil {
				log.Fatal(err)
			}
			if len(key) != 8 {
				log.Fatal(err)
			}
		}
		var ciph cipher.Block
		var iv []byte
		if *cph == "speck32" {
			ciph = simonspeck.NewSpeck32(key)
			iv = make([]byte, 4)
		} else if *cph == "simon32" {
			ciph = simonspeck.NewSimon32(key)
			iv = make([]byte, 4)
		}
		if err != nil {
			log.Fatal(err)
		}
		if *vector != "" {
			iv, _ = hex.DecodeString(*vector)
		}
		fmt.Fprintf(os.Stderr, "IV= %x\n", iv)

		var stream cipher.Stream
		if strings.ToUpper(*mode) == "CTR" {
			stream = cipher.NewCTR(ciph, iv)
		} else if strings.ToUpper(*mode) == "OFB" {
			stream = cipher.NewOFB(ciph, iv)
		}
		buf := make([]byte, 128*1<<10)
		var n int
		for {
			n, err = os.Stdin.Read(buf)
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			stream.XORKeyStream(buf[:n], buf[:n])
			if _, err := os.Stdout.Write(buf[:n]); err != nil {
				log.Fatal(err)
			}
			if err == io.EOF {
				break
			}
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if *crypt != "" && (*cph == "XOR") {
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		b := strings.TrimSuffix(string(buf.Bytes()), "\r\n")
		b = strings.TrimSuffix(string(b), "\n")
		fmt.Printf("%v\n", XOR(b, *key))
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
		}
		os.Exit(0)
	}

	if (*alg == "brainpool256r1" || *alg == "brainpool256t1" || *alg == "brainpool512r1" || *alg == "brainpool512t1" || *alg == "ecdsa" || *alg == "ECDSA" || *alg == "secp256r1" || *alg == "prime256v1" || *alg == "sm2" || *alg == "brainpool160t1" || *alg == "secp160r1" || *alg == "secp160k1" || *alg == "secp160r2" || *alg == "secp128r1" || *alg == "secp112r1" || *alg == "wtls8" || *alg == "wtls9" || *alg == "numsp256d1" || *alg == "numsp512d1" || *alg == "oakley256" || *alg == "frp256v1" || *alg == "prime192v1" || *alg == "secp192r1" || *alg == "secp192k1" || *alg == "secp256k1" || *alg == "prime192v2" || *alg == "prime192v3" || *alg == "brainpool192t1" || *alg == "oakley192" || *alg == "sm2p256v1" || *alg == "sm9p256v1" || *alg == "ecgost2001" || *alg == "ecgost2001A" || *alg == "ecgost2001B" || *alg == "ecgost2001C" || *alg == "ecgost2012" || *alg == "ecgost2012A" || *alg == "ecgost2012B" || *alg == "wapip192v1" || *alg == "fp256bn" || *alg == "fp512bn") && (*alg != "ed25519" && *alg != "X25519" && *alg != "gost2012" && *alg != "gost2001") && (*keygen || *pkeyutl == "derive" || *sign || *verify || *pkeyutl != "") {
		var privatekey *ecdsa.PrivateKey
		var pubkey ecdsa.PublicKey
		var pub *ecdsa.PublicKey
		var err error
		var pubkeyCurve elliptic.Curve

		if *alg == "brainpool256" || *alg == "brainpool256r1" {
			pubkeyCurve = brainpool.P256r1()
		} else if *alg == "brainpool256t1" {
			pubkeyCurve = brainpool.P256t1()
		} else if *alg == "brainpool512" || *alg == "brainpool512r1" {
			pubkeyCurve = brainpool.P512r1()
		} else if *alg == "brainpool512t1" {
			pubkeyCurve = brainpool.P512t1()
		} else if *alg == "ecdsa" || *alg == "secp256r1" || *alg == "prime256v1" {
			pubkeyCurve = elliptic.P256()
		} else if *alg == "sm2" {
			pubkeyCurve = sm2.P256Sm2()
		} else if *alg == "secp160r1" {
			pubkeyCurve = secp160r1.P160()
		} else if *alg == "secp160r2" {
			pubkeyCurve = secp160r2.P160()
		} else if *alg == "secp160k1" {
			pubkeyCurve = koblitz.S160()
		} else if *alg == "secp192k1" {
			pubkeyCurve = koblitz.S192()
		} else if *alg == "secp256k1" {
			pubkeyCurve = koblitz.S256()
		} else if *alg == "brainpool192t1" {
			pubkeyCurve = gocurves.Bp192()
		} else if *alg == "brainpool160t1" {
			pubkeyCurve = gocurves.Bp160()
		} else if *alg == "secp128r1" {
			pubkeyCurve = secp128r1.Secp128r1()
		} else if *alg == "secp112r1" {
			pubkeyCurve = secp112r1.P112()
		} else if *alg == "numsp256d1" {
			pubkeyCurve = gocurves.Nums256()
		} else if *alg == "numsp512d1" {
			pubkeyCurve = gocurves.Nums512()
		} else if *alg == "oakley256" {
			pubkeyCurve = oakley256.Oakley256()
		} else if *alg == "frp256v1" {
			pubkeyCurve = frp256v1.FRP256v1()
		} else if *alg == "oakley192" {
			pubkeyCurve = oakley192.Oakley192()
		} else if *alg == "prime192v1" || *alg == "secp192r1" {
			pubkeyCurve = prime192.Prime192v1()
		} else if *alg == "prime192v2" {
			pubkeyCurve = prime192.Prime192v2()
		} else if *alg == "prime192v3" {
			pubkeyCurve = prime192.Prime192v3()
		} else if *alg == "wapip192v1" {
			pubkeyCurve = wapip192v1.P192()
		} else if *alg == "sm2p256v1" {
			pubkeyCurve = sm2p256v1.P256()
		} else if *alg == "sm9p256v1" {
			pubkeyCurve = sm9p256v1.P256()
		} else if *alg == "ecgost2001" || *alg == "ecgost2001A" {
			pubkeyCurve = gost2001.GOST2001A()
		} else if *alg == "ecgost2001B" {
			pubkeyCurve = gost2001.GOST2001B()
		} else if *alg == "ecgost2001C" {
			pubkeyCurve = gost2001.GOST2001C()
		} else if *alg == "ecgost2012" || *alg == "ecgost2012A" {
			pubkeyCurve = gost2012.TC26512A()
		} else if *alg == "ecgost2012B" {
			pubkeyCurve = gost2012.TC26512B()
		} else if *alg == "fp256bn" {
			pubkeyCurve = bn.P256()
		} else if *alg == "fp512bn" {
			pubkeyCurve = bn.P512()
		} else if *alg == "wtls8" {
			pubkeyCurve = wtls.P112()
		} else if *alg == "wtls9" {
			pubkeyCurve = wtls.P160()
		}

		if *keygen {
			if *key != "" {
				privatekey, _ = ReadPrivateKeyFromHex(*key)
			} else {
				privatekey = new(ecdsa.PrivateKey)
				privatekey, err = ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			}
			pubkey = privatekey.PublicKey
			if *info != "" {
				fmt.Println("[" + *info + "]")
			}
			fmt.Println("Private= " + WritePrivateKeyToHex(privatekey))
			fmt.Println("Public= " + WritePublicKeyToHex(&pubkey))
			if *util == "chrono" {
				elapsed := time.Since(start)
				fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
			}
			os.Exit(0)
		}

		if *pkeyutl == "derive" {
			private, err := ReadPrivateKeyFromHex(*key)
			if err != nil {
				log.Fatal(err)
			}
			public, err := ReadPublicKeyFromHex(*public)
			if err != nil {
				log.Fatal(err)
			}

			b, _ := public.Curve.ScalarMult(public.X, public.Y, private.D.Bytes())

			shared := h.Sum(b.Bytes())
			fmt.Printf("Shared= %x\n", shared[0:*length/8])
			if *util == "chrono" {
				elapsed := time.Since(start)
				fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
			}
			os.Exit(0)
		}

		if *sign {
			io.Copy(h, os.Stdin)

			privatekey, err = ReadPrivateKeyFromHex(*key)
			if err != nil {
				log.Fatal(err)
			}

			signature, err := Sign(h.Sum(nil), privatekey)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s-%s= %x\n", strings.ToUpper(*alg), strings.ToUpper(*md), signature)
			if *util == "chrono" {
				elapsed := time.Since(start)
				fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
			}
			os.Exit(0)
		}

		if *verify {
			io.Copy(h, os.Stdin)

			pub, err = ReadPublicKeyFromHex(*key)
			if err != nil {
				log.Fatal(err)
			}

			sig, _ := hex.DecodeString(*sig)

			verifystatus := Verify(h.Sum(nil), sig, pub)
			fmt.Println(verifystatus)
			if verifystatus == false {
				os.Exit(1)
			}
			if *util == "chrono" {
				elapsed := time.Since(start)
				fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
			}
			os.Exit(0)
		}

		if *pkeyutl == "enc" && (*alg == "brainpool160t1" || *alg == "secp160r1" || *alg == "secp160k1" || *alg == "secp160r2" || *alg == "wtls9") {
			public, err := ReadPublicKeyFromHex160(*key)
			if err != nil {
				log.Fatal(err)
			}
			buf := bytes.NewBuffer(nil)
			data := os.Stdin
			io.Copy(buf, data)
			scanner := string(buf.Bytes())
			ciphertxt, err := eccrypt160.EncryptAsn1(public, []byte(scanner), rand.Reader)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%x\n", ciphertxt)
			os.Exit(0)
		}

		if *pkeyutl == "enc" && (*alg == "prime192v1" || *alg == "secp192r1" || *alg == "secp192k1" || *alg == "prime192v2" || *alg == "prime192v3" || *alg == "brainpool192t1" || *alg == "oakley192" || *alg == "wapip192v1") {
			public, err := ReadPublicKeyFromHex192(*key)
			if err != nil {
				log.Fatal(err)
			}
			buf := bytes.NewBuffer(nil)
			data := os.Stdin
			io.Copy(buf, data)
			scanner := string(buf.Bytes())
			ciphertxt, err := eccrypt192.EncryptAsn1(public, []byte(scanner), rand.Reader)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%x\n", ciphertxt)
			os.Exit(0)
		}

		if *pkeyutl == "enc" && (*alg == "brainpool256" || *alg == "brainpool256t1" || *alg == "brainpool256t1" || *alg == "ecdsa" || *alg == "ECDSA" || *alg == "secp256r1" || *alg == "prime256v1" || *alg == "secp256k1" || *alg == "sm2p256v1" || *alg == "numsp256d1" || *alg == "oakley256" || *alg == "frp256v1" || *alg == "ecgost2001" || *alg == "ecgost2001A" || *alg == "ecgost2001B" || *alg == "ecgost2001C" || *alg == "sm2p256v1" || *alg == "sm9p256v1" || *alg == "fp256bn") {
			public, err := ReadPublicKeyFromHex256(*key)
			if err != nil {
				log.Fatal(err)
			}
			buf := bytes.NewBuffer(nil)
			data := os.Stdin
			io.Copy(buf, data)
			scanner := string(buf.Bytes())
			ciphertxt, err := eccrypt.EncryptAsn1(public, []byte(scanner), rand.Reader)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%x\n", ciphertxt)
			os.Exit(0)
		}

		if *pkeyutl == "enc" && (*alg == "brainpool512" || *alg == "brainpool512t1" || *alg == "brainpool512t1" || *alg == "numsp512d1" || *alg == "ecgost2012" || *alg == "ecgost2012A" || *alg == "ecgost2012B" || *alg == "fp512bn") {
			public, err := ReadPublicKeyFromHex512(*key)
			if err != nil {
				log.Fatal(err)
			}
			buf := bytes.NewBuffer(nil)
			data := os.Stdin
			io.Copy(buf, data)
			scanner := string(buf.Bytes())
			ciphertxt, err := eccrypt512.EncryptAsn1(public, []byte(scanner), rand.Reader)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%x\n", ciphertxt)
			os.Exit(0)
		}

		if *pkeyutl == "dec" && (*alg == "brainpool160t1" || *alg == "secp160r1" || *alg == "secp160k1" || *alg == "secp160r2" || *alg == "wtls9") {
			private, err := ReadPrivateKeyFromHex160(*key)
			if err != nil {
				log.Fatal(err)
			}
			buf := bytes.NewBuffer(nil)
			data := os.Stdin
			io.Copy(buf, data)
			scanner := string(buf.Bytes())
			str, _ := hex.DecodeString(string(scanner))
			plaintxt, err := eccrypt160.DecryptAsn1(private, []byte(str))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s\n", plaintxt)
			os.Exit(0)
		}

		if *pkeyutl == "dec" && (*alg == "prime192v1" || *alg == "secp192r1" || *alg == "secp192k1" || *alg == "prime192v2" || *alg == "prime192v3" || *alg == "brainpool192t1" || *alg == "oakley192" || *alg == "wapip192v1") {
			private, err := ReadPrivateKeyFromHex192(*key)
			if err != nil {
				log.Fatal(err)
			}
			buf := bytes.NewBuffer(nil)
			data := os.Stdin
			io.Copy(buf, data)
			scanner := string(buf.Bytes())
			str, _ := hex.DecodeString(string(scanner))
			plaintxt, err := eccrypt192.DecryptAsn1(private, []byte(str))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s\n", plaintxt)
			os.Exit(0)
		}

		if *pkeyutl == "dec" && (*alg == "brainpool256r1" || *alg == "brainpool256t1" || *alg == "ecdsa" || *alg == "ECDSA" || *alg == "secp256r1" || *alg == "prime256v1" || *alg == "secp256k1" || *alg == "sm2p256v1" || *alg == "numsp256d1" || *alg == "oakley256" || *alg == "frp256v1" || *alg == "ecgost2001" || *alg == "ecgost2001A" || *alg == "ecgost2001B" || *alg == "ecgost2001C" || *alg == "sm2p256v1" || *alg == "sm9p256v1" || *alg == "fp256bn") {
			private, err := ReadPrivateKeyFromHex256(*key)
			if err != nil {
				log.Fatal(err)
			}
			buf := bytes.NewBuffer(nil)
			data := os.Stdin
			io.Copy(buf, data)
			scanner := string(buf.Bytes())
			str, _ := hex.DecodeString(string(scanner))
			plaintxt, err := eccrypt.DecryptAsn1(private, []byte(str))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s\n", plaintxt)
			os.Exit(0)
		}

		if *pkeyutl == "dec" && (*alg == "brainpool512r1" || *alg == "brainpool512t1" || *alg == "numsp512d1" || *alg == "numsp512t1" || *alg == "ecgost2012" || *alg == "ecgost2012A" || *alg == "ecgost2012B" || *alg == "fp512bn") {
			private, err := ReadPrivateKeyFromHex512(*key)
			if err != nil {
				log.Fatal(err)
			}
			buf := bytes.NewBuffer(nil)
			data := os.Stdin
			io.Copy(buf, data)
			scanner := string(buf.Bytes())
			str, _ := hex.DecodeString(string(scanner))
			plaintxt, err := eccrypt512.DecryptAsn1(private, []byte(str))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s\n", plaintxt)
			os.Exit(0)
		}

		var priv *sm2.PrivateKey
		var public *sm2.PublicKey

		if *pkeyutl == "enc" && *alg == "sm2" {
			public, err = ReadSM2PublicKeyFromHex(*key)
			if err != nil {
				log.Fatal(err)
			}
			buf := bytes.NewBuffer(nil)
			data := os.Stdin
			io.Copy(buf, data)
			scanner := string(buf.Bytes())
			ciphertxt, err := public.EncryptAsn1([]byte(scanner), rand.Reader)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%x\n", ciphertxt)
			if *util == "chrono" {
				elapsed := time.Since(start)
				fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
			}
			os.Exit(0)
		}

		if *pkeyutl == "dec" && *alg == "sm2" {
			priv, err = ReadSM2PrivateKeyFromHex(*key)
			if err != nil {
				log.Fatal(err)
			}
			buf := bytes.NewBuffer(nil)
			data := os.Stdin
			io.Copy(buf, data)
			scanner := string(buf.Bytes())
			str, _ := hex.DecodeString(string(scanner))
			plaintxt, err := priv.DecryptAsn1([]byte(str))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s\n", plaintxt)
			if *util == "chrono" {
				elapsed := time.Since(start)
				fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
			}
			os.Exit(0)
		}
	}

	if (*alg == "gost2001" || *alg == "gost2001A" || *alg == "gost2001B" || *alg == "gost2001C" || *alg == "gost2001XA" || *alg == "gost2001XB" || *alg == "gost2012_256" || *alg == "gost2012_256A" || *alg == "gost2012_256B" || *alg == "gost2012_256C" || *alg == "gost2012_256D" || *alg == "gost2012_512" || *alg == "gost2012_512A" || *alg == "gost2012_512B" || *alg == "gost2012_512C") && (*alg != "ed25519" && *alg != "X25519" && *alg != "x25519" && *alg != "secp256k1") && (*keygen || *pkeyutl == "derive" || *sign || *verify) {
		var err error
		var curve *gost3410.Curve
		if *alg == "gost2001" || *alg == "gost2001A" {
			curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()
		} else if *alg == "gost2001B" {
			curve = gost3410.CurveIdGostR34102001CryptoProBParamSet()
		} else if *alg == "gost2001C" {
			curve = gost3410.CurveIdGostR34102001CryptoProCParamSet()
		} else if *alg == "gost2001XA" {
			curve = gost3410.CurveIdGostR34102001CryptoProXchAParamSet()
		} else if *alg == "gost2001XB" {
			curve = gost3410.CurveIdGostR34102001CryptoProXchBParamSet()
		} else if *alg == "gost2012_256" || *alg == "gost2012_256A" {
			curve = gost3410.CurveIdtc26gost34102012256paramSetA()
		} else if *alg == "gost2012_256B" {
			curve = gost3410.CurveIdtc26gost34102012256paramSetB()
		} else if *alg == "gost2012_256C" {
			curve = gost3410.CurveIdtc26gost34102012256paramSetC()
		} else if *alg == "gost2012_256D" {
			curve = gost3410.CurveIdtc26gost34102012256paramSetD()
		} else if *alg == "gost2012_512" || *alg == "gost2012_512A" {
			curve = gost3410.CurveIdtc26gost341012512paramSetA()
		} else if *alg == "gost2012_512B" {
			curve = gost3410.CurveIdtc26gost341012512paramSetB()
		} else if *alg == "gost2012_512C" {
			curve = gost3410.CurveIdtc26gost34102012512paramSetC()
		}

		if *pkeyutl == "derive" {
			var prvRaw []byte
			var pubRaw []byte
			var prv *gost3410.PrivateKey
			var pub *gost3410.PublicKey

			prvRaw, err = hex.DecodeString(*key)
			if err != nil {
				log.Fatal(err)
			}
			if len(prvRaw) != 256/8 && len(prvRaw) != 512/8 {
				log.Fatal(err, "private key has wrong length")
			}
			prv, err = gost3410.NewPrivateKey(curve, prvRaw)
			if err != nil {
				log.Fatal(err)
			}
			pubRaw, err = hex.DecodeString(*public)
			if err != nil {
				log.Fatal(err)
			}
			if len(pubRaw) != 2*256/8 && len(pubRaw) != 2*512/8 {
				log.Fatal(err, "public key has wrong length")
			}
			pub, err = gost3410.NewPublicKey(curve, pubRaw)
			if err != nil {
				log.Fatal(err)
			}

			shared, err := prv.KEK2012256(pub, big.NewInt(1))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("Shared=", hex.EncodeToString(shared[0:*length/8]))
			if *util == "chrono" {
				elapsed := time.Since(start)
				fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
			}
			os.Exit(0)
		}

		if *keygen {
			var prvRaw []byte
			var pubRaw []byte
			var prv *gost3410.PrivateKey
			var pub *gost3410.PublicKey

			var curve *gost3410.Curve
			if *alg == "gost2001" || *alg == "gost2001A" {
				curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()
				if *key != "" {
					prvRaw, _ = hex.DecodeString(*key)
				} else {
					prvRaw = make([]byte, 256/8)
					_, err = io.ReadFull(rand.Reader, prvRaw)
					if err != nil {
						log.Fatal(err)

					}
				}
			} else if *alg == "gost2001B" {
				curve = gost3410.CurveIdGostR34102001CryptoProBParamSet()
				if *key != "" {
					prvRaw, _ = hex.DecodeString(*key)
				} else {
					prvRaw = make([]byte, 256/8)
					_, err = io.ReadFull(rand.Reader, prvRaw)
					if err != nil {
						log.Fatal(err)

					}
				}
			} else if *alg == "gost2001C" {
				curve = gost3410.CurveIdGostR34102001CryptoProCParamSet()
				if *key != "" {
					prvRaw, _ = hex.DecodeString(*key)
				} else {
					prvRaw = make([]byte, 256/8)
					_, err = io.ReadFull(rand.Reader, prvRaw)
					if err != nil {
						log.Fatal(err)

					}
				}
			} else if *alg == "gost2001XA" {
				curve = gost3410.CurveIdGostR34102001CryptoProXchAParamSet()
				if *key != "" {
					prvRaw, _ = hex.DecodeString(*key)
				} else {
					prvRaw = make([]byte, 256/8)
					_, err = io.ReadFull(rand.Reader, prvRaw)
					if err != nil {
						log.Fatal(err)

					}
				}
			} else if *alg == "gost2001XB" {
				curve = gost3410.CurveIdGostR34102001CryptoProXchBParamSet()
				if *key != "" {
					prvRaw, _ = hex.DecodeString(*key)
				} else {
					prvRaw = make([]byte, 256/8)
					_, err = io.ReadFull(rand.Reader, prvRaw)
					if err != nil {
						log.Fatal(err)

					}
				}
			} else if *alg == "gost2012_256" || *alg == "gost2012_256A" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetA()
				if *key != "" {
					prvRaw, _ = hex.DecodeString(*key)
				} else {
					prvRaw = make([]byte, 256/8)
					_, err = io.ReadFull(rand.Reader, prvRaw)
					if err != nil {
						log.Fatal(err)

					}
				}
			} else if *alg == "gost2012_256B" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetB()
				if *key != "" {
					prvRaw, _ = hex.DecodeString(*key)
				} else {
					prvRaw = make([]byte, 256/8)
					_, err = io.ReadFull(rand.Reader, prvRaw)
					if err != nil {
						log.Fatal(err)

					}
				}
			} else if *alg == "gost2012_256C" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetC()
				if *key != "" {
					prvRaw, _ = hex.DecodeString(*key)
				} else {
					prvRaw = make([]byte, 256/8)
					_, err = io.ReadFull(rand.Reader, prvRaw)
					if err != nil {
						log.Fatal(err)

					}
				}
			} else if *alg == "gost2012_256D" {
				curve = gost3410.CurveIdtc26gost34102012256paramSetD()
				if *key != "" {
					prvRaw, _ = hex.DecodeString(*key)
				} else {
					prvRaw = make([]byte, 256/8)
					_, err = io.ReadFull(rand.Reader, prvRaw)
					if err != nil {
						log.Fatal(err)

					}
				}
			} else if *alg == "gost2012_512" || *alg == "gost2012_512A" {
				curve = gost3410.CurveIdtc26gost341012512paramSetA()
				if *key != "" {
					prvRaw, _ = hex.DecodeString(*key)
				} else {
					prvRaw = make([]byte, 512/8)
					_, err = io.ReadFull(rand.Reader, prvRaw)
					if err != nil {
						log.Fatal(err)

					}
				}
			} else if *alg == "gost2012_512B" {
				curve = gost3410.CurveIdtc26gost341012512paramSetB()
				if *key != "" {
					prvRaw, _ = hex.DecodeString(*key)
				} else {
					prvRaw = make([]byte, 512/8)
					_, err = io.ReadFull(rand.Reader, prvRaw)
					if err != nil {
						log.Fatal(err)

					}
				}
			} else if *alg == "gost2012_512C" {
				curve = gost3410.CurveIdtc26gost34102012512paramSetC()
				if *key != "" {
					prvRaw, _ = hex.DecodeString(*key)
				} else {
					prvRaw = make([]byte, 512/8)
					_, err = io.ReadFull(rand.Reader, prvRaw)
					if err != nil {
						log.Fatal(err)

					}
				}
			}

			if *info != "" {
				fmt.Println("[" + *info + "]")
			}

			fmt.Println("Private=", hex.EncodeToString(prvRaw))

			prv, err = gost3410.NewPrivateKey(curve, prvRaw)
			if err != nil {
				log.Fatal(err)
			}

			pub, err = prv.PublicKey()
			if err != nil {
				log.Fatal(err)
			}
			pubRaw = pub.Raw()
			fmt.Println("Public=", hex.EncodeToString(pubRaw))

			if *util == "chrono" {
				elapsed := time.Since(start)
				fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
			}
			os.Exit(0)
		}

		if *sign || *verify {

			buf := bytes.NewBuffer(nil)
			scanner := os.Stdin
			io.Copy(buf, scanner)
			hash := string(buf.Bytes())

			var prvRaw []byte
			var pubRaw []byte
			var prv *gost3410.PrivateKey
			var pub *gost3410.PublicKey

			var inputsig []byte
			inputsig, err = hex.DecodeString(*sig)
			if err != nil {
				log.Fatal(err)
			}

			if *sign {
				data := []byte(hash)
				hasher := h
				_, err := hasher.Write(data)
				if err != nil {
					log.Fatal(err)
				}
				dgst := hasher.Sum(nil)

				prvRaw, err = hex.DecodeString(*key)
				if err != nil {
					log.Fatal(err)
				}
				if len(prvRaw) != 256/8 && len(prvRaw) != 512/8 {
					log.Fatal(err, "private key has wrong length")
				}
				prv, err = gost3410.NewPrivateKey(curve, prvRaw)
				if err != nil {
					log.Fatal(err)
				}

				signature, err := prv.Sign(rand.Reader, dgst, nil)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Printf("%s-%s= %x\n", strings.ToUpper(*alg), strings.ToUpper(*md), signature)
				if *util == "chrono" {
					elapsed := time.Since(start)
					fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
				}
				os.Exit(0)
			}

			if *verify {
				data := []byte(hash)
				hasher := h
				_, err := hasher.Write(data)
				if err != nil {
					log.Fatal(err)
				}
				dgst := hasher.Sum(nil)

				pubRaw, err = hex.DecodeString(*key)
				if err != nil {
					log.Fatal(err)
				}
				if len(pubRaw) != 2*256/8 && len(pubRaw) != 2*512/8 {
					log.Fatal(err, "public key has wrong length")
				}
				pub, err = gost3410.NewPublicKey(curve, pubRaw)
				if err != nil {
					log.Fatal(err)
				}
				isValid, err := pub.VerifyDigest(dgst, inputsig)
				if err != nil {
					log.Fatal(err)
				}
				if !isValid {
					log.Fatal("signature is invalid")
					os.Exit(1)
				}
				fmt.Println("Verify correct.")
				if *util == "chrono" {
					elapsed := time.Since(start)
					fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
				}
				os.Exit(0)
			}
		}
	}

	if (*alg == "ed25519" || *alg == "Ed25519" || *alg == "x25519" || *alg == "X25519") && (*alg != "gost2012_256" && *alg != "gost2012_512" && *alg != "secp256k1") && (*keygen || *pkeyutl == "derive" || *sign || *verify) {
		var privatekey ed25519.PrivateKey
		var publickey ed25519.PublicKey

		if *keygen && (*alg == "x25519" || *alg == "X25519") {
			_, _ = io.ReadFull(rand.Reader, privatekey[:])

			var privateKey *[32]byte
			var publicKey *[32]byte

			privateKey, publicKey, _ = GenerateKey()

			if *info != "" {
				fmt.Println("[" + *info + "]")
			}
			fmt.Printf("Private= %x\n", *privateKey)
			fmt.Printf("Public= %x\n", *publicKey)
			os.Exit(0)
		}

		if *keygen && (*alg == "ed25519" || *alg == "Ed25519" || *alg == "curve25519") {
			_, _ = io.ReadFull(rand.Reader, privatekey[:])

			publickey, privatekey, _ = ed25519.GenerateKey(rand.Reader)

			if *info != "" {
				fmt.Println("[" + *info + "]")
			}
			fmt.Printf("Private= %x\n", privatekey)
			fmt.Printf("Public= %x\n", publickey)
			os.Exit(0)
		}

		if *pkeyutl == "derive" {
			privatekey, err := hex.DecodeString(*key)
			if err != nil {
				log.Fatal(err)
			}
			if len(privatekey) != 32 {
				log.Fatal("curve25519: bad private key length.")
				os.Exit(1)
			}
			publickey, err := hex.DecodeString(*public)
			if err != nil {
				log.Fatal(err)
			}

			var privateKey [32]byte
			copy(privateKey[:], []byte(privatekey))
			var publicKey [32]byte
			copy(publicKey[:], []byte(publickey))

			var secret []byte
			secret = GenerateSharedSecret(privateKey, publicKey)

			fmt.Printf("Shared= %x\n", secret[0:*length/8])

			if *util == "chrono" {
				elapsed := time.Since(start)
				fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
			}
			os.Exit(0)
		}

		if *sign {
			privatekey, _ := hex.DecodeString(*key)
			if len(privatekey) != ed25519.PrivateKeySize {
				log.Fatal("ed25519: bad private key length.")
			}

			buf := bytes.NewBuffer(nil)
			data := os.Stdin
			io.Copy(buf, data)
			sig := ed25519.Sign(privatekey, buf.Bytes())
			fmt.Printf("%s= %x\n", strings.ToUpper(*alg), sig)
			if *util == "chrono" {
				elapsed := time.Since(start)
				fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
			}
			os.Exit(0)
		}

		if *verify {
			publickey, _ := hex.DecodeString(*key)
			if len(publickey) != ed25519.PublicKeySize {
				log.Fatal("ed25519: bad private key length.")
			}

			buf := bytes.NewBuffer(nil)
			data := os.Stdin
			io.Copy(buf, data)
			sig, _ := hex.DecodeString(*sig)
			ver := ed25519.Verify(publickey, buf.Bytes(), sig)
			fmt.Printf("%t\n", ver)
			if ver == false {
				os.Exit(1)
			}

			if *util == "chrono" {
				elapsed := time.Since(start)
				fmt.Fprintln(os.Stderr, "\nProcess took:", elapsed)
			}
			os.Exit(0)
		}
	}

	if *target == "-" && *md == "poly1305" {
		var keyx [32]byte
		copy(keyx[:], []byte(*key))
		h := poly1305.New(&keyx)
		io.Copy(h, os.Stdin)
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "Process took:", elapsed)
		}
		os.Exit(0)
	}

	if *target == "-" && (*md == "haraka" || *md == "haraka256") {
		xkey := new([32]byte)
		gkey := new([32]byte)
		b, _ := ioutil.ReadAll(os.Stdin)
		copy(xkey[:], b)
		haraka.Haraka256(gkey, xkey)
		fmt.Printf("%x\n", gkey[:])
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "Process took:", elapsed)
		}
		os.Exit(0)
	}

	if *target == "-" && *md == "haraka512" {
		xkey := new([64]byte)
		gkey := new([32]byte)
		b, _ := ioutil.ReadAll(os.Stdin)
		copy(xkey[:], b)
		haraka.Haraka512(gkey, xkey)
		fmt.Printf("%x\n", gkey[:])
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "Process took:", elapsed)
		}
		os.Exit(0)
	}

	if *target != "" && *rec == false && *md == "poly1305" {
		files, err := filepath.Glob(*target)
		if err != nil {
			log.Fatal(err)
		}
		for _, match := range files {
			var keyx [32]byte
			copy(keyx[:], []byte(*key))
			h := poly1305.New(&keyx)
			f, err := os.Open(match)
			if err != nil {
				log.Fatal(err)
			}
			file, err := os.Stat(match)
			if file.IsDir() {
			} else {
				if _, err := io.Copy(h, f); err != nil {
					log.Fatal(err)
				}
				fmt.Println(hex.EncodeToString(h.Sum(nil)), "*"+f.Name())
			}
			f.Close()
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "Process took:", elapsed)
		}
		os.Exit(0)
	}

	if *target != "" && *rec == true && *md == "poly1305" {
		err := filepath.Walk(filepath.Dir(*target),
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				file, err := os.Stat(path)
				if file.IsDir() {
				} else {
					filename := filepath.Base(path)
					pattern := filepath.Base(*target)
					matched, err := filepath.Match(pattern, filename)
					if err != nil {
						fmt.Println(err)
					}
					if matched {
						var keyx [32]byte
						copy(keyx[:], []byte(*key))
						h := poly1305.New(&keyx)
						f, err := os.Open(path)
						if err != nil {
							log.Fatal(err)
						}
						if _, err := io.Copy(h, f); err != nil {
							log.Fatal(err)
						}
						f.Close()
						fmt.Println(hex.EncodeToString(h.Sum(nil)), "*"+f.Name())
					}
				}
				return nil
			})
		if err != nil {
			log.Println(err)
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "Process took:", elapsed)
		}
		os.Exit(0)
	}

	if *check != "" && *md == "poly1305" {
		var file io.Reader
		var err error
		if *check == "-" {
			file = os.Stdin
		} else {
			file, err = os.Open(*check)
			if err != nil {
				log.Fatalf("failed opening file: %s", err)
			}
		}
		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)
		var txtlines []string
		for scanner.Scan() {
			txtlines = append(txtlines, scanner.Text())
		}
		var exit int
		for _, eachline := range txtlines {
			lines := strings.Split(string(eachline), " *")
			if strings.Contains(string(eachline), " *") {
				var keyx [32]byte
				copy(keyx[:], []byte(*key))
				h := poly1305.New(&keyx)
				_, err := os.Stat(lines[1])
				if err == nil {
					f, err := os.Open(lines[1])
					if err != nil {
						log.Fatal(err)
					}
					io.Copy(h, f)
					f.Close()

					if hex.EncodeToString(h.Sum(nil)) == lines[0] {
						fmt.Println(lines[1]+"\t", "OK")
					} else {
						fmt.Println(lines[1]+"\t", "FAILED")
						exit = 1
					}

				} else {
					fmt.Println(lines[1]+"\t", "Not found!")
					exit = 1
				}
			}
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "Process took:", elapsed)
		}
		os.Exit(exit)
	}

	if *target == "-" {
		var h hash.Hash
		if *md == "sha256" {
			h = sha256.New()
		} else if *md == "sha512" {
			h = sha512.New()
		} else if *md == "sha512_256" {
			h = sha512.New512_256()
		} else if *md == "md5" {
			h = md5.New()
		} else if *md == "sha1" {
			h = sha1.New()
		} else if *md == "rmd128" {
			h = ripemd.New128()
		} else if *md == "rmd160" {
			h = ripemd.New160()
		} else if *md == "rmd256" {
			h = ripemd.New256()
		} else if *md == "sha3_256" {
			h = sha3.New256()
		} else if *md == "sha3_512" {
			h = sha3.New512()
		} else if *md == "keccak256" {
			h = sha3.NewLegacyKeccak256()
		} else if *md == "keccak512" {
			h = sha3.NewLegacyKeccak512()
		} else if *md == "whirlpool" {
			h = whirlpool.New()
		} else if *md == "blake256" {
			h = blake256.New()
		} else if *md == "blake512" {
			h = blake512.New()
		} else if *md == "blake2b256" {
			h, _ = blake2b.New256([]byte(*key))
		} else if *md == "blake2b512" {
			h, _ = blake2b.New512([]byte(*key))
		} else if *md == "blake2s256" {
			h, _ = blake2s.New256([]byte(*key))
		} else if *md == "blake2s128" {
			h, _ = blake2s.New128([]byte(*key))
		} else if *md == "skein256" {
			h = skein256.New256([]byte(*key))
		} else if *md == "skein512_256" {
			h = skein.New256([]byte(*key))
		} else if *md == "skein512" {
			h = skein.New512([]byte(*key))
		} else if *md == "groestl" {
			h = groestl.New256()
		} else if *md == "groestl512" {
			h = groestl512.New512()
		} else if *md == "jh" {
			h = jh.New256()
		} else if *md == "tiger" {
			h = tiger.New()
		} else if *md == "tiger128" {
			h = tiger128.New()
		} else if *md == "tiger160" {
			h = tiger160.New()
		} else if *md == "tiger2" {
			h = tiger.New2()
		} else if *md == "tiger2_128" {
			h = tiger128.New2()
		} else if *md == "tiger2_160" {
			h = tiger160.New2()
		} else if *md == "sm3" {
			h = sm3.New()
		} else if *md == "gost94" {
			h = gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		} else if *md == "streebog256" {
			h = gost34112012256.New()
		} else if *md == "streebog512" {
			h = gost34112012512.New()
		} else if *md == "stribog256" {
			h = gostribog.New256()
		} else if *md == "stribog512" {
			h = gostribog.New512()
		} else if *md == "djb" {
			h = NewDjb32()
		} else if *md == "djba" {
			h = NewDjb32a()
		} else if *md == "elf32" {
			h = NewElf32()
		} else if *md == "sdbm" {
			h = NewSDBM32()
		} else if *md == "siphash" || *md == "siphash128" {
			var xkey [16]byte
			copy(xkey[:], []byte(*key))
			h, _ = siphash.New128(xkey[:])
		} else if *md == "siphash64" {
			var xkey [16]byte
			copy(xkey[:], []byte(*key))
			h, _ = siphash.New64(xkey[:])
		} else if *md == "lsh256" {
			h = lsh256.New()
		} else if *md == "lsh512" {
			h = lsh512.New()
		} else if *md == "lsh512_256" {
			h = lsh512.New256()
		} else if *md == "blake3" {
			h = blake3.New()
		} else if *md == "cubehash" {
			h = cubehash.New()
		} else if *md == "seahash" {
			h = seahash.New()
		} else if *md == "8-bit" {
			h = pearson.New()
		} else if *md == "crc24" {
			h = crc24.New()
		}
		io.Copy(h, os.Stdin)
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "Process took:", elapsed)
		}
		os.Exit(0)
	}

	if *target != "" && *rec == false {
		files, err := filepath.Glob(*target)
		if err != nil {
			log.Fatal(err)
		}
		for _, match := range files {
			f, err := os.Open(match)
			if err != nil {
				log.Fatal(err)
			}
			file, err := os.Stat(match)
			if file.IsDir() {
			} else {
				var h hash.Hash
				if *md == "sha256" {
					h = sha256.New()
				} else if *md == "sha512" {
					h = sha512.New()
				} else if *md == "sha512_256" {
					h = sha512.New512_256()
				} else if *md == "md5" {
					h = md5.New()
				} else if *md == "sha1" {
					h = sha1.New()
				} else if *md == "rmd128" {
					h = ripemd.New128()
				} else if *md == "rmd160" {
					h = ripemd.New160()
				} else if *md == "rmd256" {
					h = ripemd.New256()
				} else if *md == "sha3_256" {
					h = sha3.New256()
				} else if *md == "sha3_512" {
					h = sha3.New512()
				} else if *md == "keccak256" {
					h = sha3.NewLegacyKeccak256()
				} else if *md == "keccak512" {
					h = sha3.NewLegacyKeccak512()
				} else if *md == "whirlpool" {
					h = whirlpool.New()
				} else if *md == "blake256" {
					h = blake256.New()
				} else if *md == "blake512" {
					h = blake512.New()
				} else if *md == "blake2b256" {
					h, _ = blake2b.New256([]byte(*key))
				} else if *md == "blake2b512" {
					h, _ = blake2b.New512([]byte(*key))
				} else if *md == "blake2s256" {
					h, _ = blake2s.New256([]byte(*key))
				} else if *md == "blake2s128" {
					h, _ = blake2s.New128([]byte(*key))
				} else if *md == "groestl" {
					h = groestl.New256()
				} else if *md == "groestl512" {
					h = groestl512.New512()
				} else if *md == "skein256" {
					h = skein256.New256([]byte(*key))
				} else if *md == "skein512_256" {
					h = skein.New256([]byte(*key))
				} else if *md == "skein512" {
					h = skein.New512([]byte(*key))
				} else if *md == "jh" {
					h = jh.New256()
				} else if *md == "tiger" {
					h = tiger.New()
				} else if *md == "tiger128" {
					h = tiger128.New()
				} else if *md == "tiger160" {
					h = tiger160.New()
				} else if *md == "tiger2" {
					h = tiger.New2()
				} else if *md == "tiger2_128" {
					h = tiger128.New2()
				} else if *md == "tiger2_160" {
					h = tiger160.New2()
				} else if *md == "sm3" {
					h = sm3.New()
				} else if *md == "gost94" {
					h = gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
				} else if *md == "streebog256" {
					h = gost34112012256.New()
				} else if *md == "streebog512" {
					h = gost34112012512.New()
				} else if *md == "stribog256" {
					h = gostribog.New256()
				} else if *md == "stribog512" {
					h = gostribog.New512()
				} else if *md == "djb" {
					h = NewDjb32()
				} else if *md == "djba" {
					h = NewDjb32a()
				} else if *md == "elf32" {
					h = NewElf32()
				} else if *md == "sdbm" {
					h = NewSDBM32()
				} else if *md == "siphash" || *md == "siphash128" {
					var xkey [16]byte
					copy(xkey[:], []byte(*key))
					h, _ = siphash.New128(xkey[:])
				} else if *md == "siphash64" {
					var xkey [16]byte
					copy(xkey[:], []byte(*key))
					h, _ = siphash.New64(xkey[:])
				} else if *md == "lsh256" {
					h = lsh256.New()
				} else if *md == "lsh512" {
					h = lsh512.New()
				} else if *md == "lsh512_256" {
					h = lsh512.New256()
				} else if *md == "blake3" {
					h = blake3.New()
				} else if *md == "cubehash" {
					h = cubehash.New()
				} else if *md == "seahash" {
					h = seahash.New()
				} else if *md == "8-bit" {
					h = pearson.New()
				} else if *md == "crc24" {
					h = crc24.New()
				}

				if _, err := io.Copy(h, f); err != nil {
					log.Fatal(err)
				}
				fmt.Println(hex.EncodeToString(h.Sum(nil)), "*"+f.Name())
			}
			f.Close()
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "Process took:", elapsed)
		}
		os.Exit(0)
	}

	if *target != "" && *rec == true {
		err := filepath.Walk(filepath.Dir(*target),
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				file, err := os.Stat(path)
				if file.IsDir() {
				} else {
					filename := filepath.Base(path)
					pattern := filepath.Base(*target)
					matched, err := filepath.Match(pattern, filename)
					if err != nil {
						fmt.Println(err)
					}
					if matched {
						var h hash.Hash
						if *md == "sha256" {
							h = sha256.New()
						} else if *md == "sha512" {
							h = sha512.New()
						} else if *md == "sha512_256" {
							h = sha512.New512_256()
						} else if *md == "md5" {
							h = md5.New()
						} else if *md == "sha1" {
							h = sha1.New()
						} else if *md == "rmd128" {
							h = ripemd.New128()
						} else if *md == "rmd160" {
							h = ripemd.New160()
						} else if *md == "rmd256" {
							h = ripemd.New256()
						} else if *md == "sha3_256" {
							h = sha3.New256()
						} else if *md == "sha3_512" {
							h = sha3.New512()
						} else if *md == "keccak256" {
							h = sha3.NewLegacyKeccak256()
						} else if *md == "keccak512" {
							h = sha3.NewLegacyKeccak512()
						} else if *md == "whirlpool" {
							h = whirlpool.New()
						} else if *md == "blake256" {
							h = blake256.New()
						} else if *md == "blake512" {
							h = blake512.New()
						} else if *md == "blake2b256" {
							h, _ = blake2b.New256([]byte(*key))
						} else if *md == "blake2b512" {
							h, _ = blake2b.New512([]byte(*key))
						} else if *md == "blake2s256" {
							h, _ = blake2s.New256([]byte(*key))
						} else if *md == "blake2s128" {
							h, _ = blake2s.New128([]byte(*key))
						} else if *md == "groestl" {
							h = groestl.New256()
						} else if *md == "groestl512" {
							h = groestl512.New512()
						} else if *md == "skein256" {
							h = skein256.New256([]byte(*key))
						} else if *md == "skein512_256" {
							h = skein.New256([]byte(*key))
						} else if *md == "skein512" {
							h = skein.New512([]byte(*key))
						} else if *md == "jh" {
							h = jh.New256()
						} else if *md == "tiger" {
							h = tiger.New()
						} else if *md == "tiger128" {
							h = tiger128.New()
						} else if *md == "tiger160" {
							h = tiger160.New()
						} else if *md == "tiger2" {
							h = tiger.New2()
						} else if *md == "tiger2_128" {
							h = tiger128.New2()
						} else if *md == "tiger2_160" {
							h = tiger160.New2()
						} else if *md == "sm3" {
							h = sm3.New()
						} else if *md == "gost94" {
							h = gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
						} else if *md == "streebog256" {
							h = gost34112012256.New()
						} else if *md == "streebog512" {
							h = gost34112012512.New()
						} else if *md == "stribog256" {
							h = gostribog.New256()
						} else if *md == "stribog512" {
							h = gostribog.New512()
						} else if *md == "djb" {
							h = NewDjb32()
						} else if *md == "djba" {
							h = NewDjb32a()
						} else if *md == "elf32" {
							h = NewElf32()
						} else if *md == "sdbm" {
							h = NewSDBM32()
						} else if *md == "siphash" || *md == "siphash128" {
							var xkey [16]byte
							copy(xkey[:], []byte(*key))
							h, _ = siphash.New128(xkey[:])
						} else if *md == "siphash64" {
							var xkey [16]byte
							copy(xkey[:], []byte(*key))
							h, _ = siphash.New64(xkey[:])
						} else if *md == "lsh256" {
							h = lsh256.New()
						} else if *md == "lsh512" {
							h = lsh512.New()
						} else if *md == "lsh512_256" {
							h = lsh512.New256()
						} else if *md == "blake3" {
							h = blake3.New()
						} else if *md == "cubehash" {
							h = cubehash.New()
						} else if *md == "seahash" {
							h = seahash.New()
						} else if *md == "8-bit" {
							h = pearson.New()
						} else if *md == "crc24" {
							h = crc24.New()
						}
						f, err := os.Open(path)
						if err != nil {
							log.Fatal(err)
						}
						if _, err := io.Copy(h, f); err != nil {
							log.Fatal(err)
						}
						f.Close()
						fmt.Println(hex.EncodeToString(h.Sum(nil)), "*"+f.Name())
					}
				}
				return nil
			})
		if err != nil {
			log.Println(err)
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "Process took:", elapsed)
		}
		os.Exit(0)
	}

	if *check != "" {
		var file io.Reader
		var err error
		if *check == "-" {
			file = os.Stdin
		} else {
			file, err = os.Open(*check)
			if err != nil {
				log.Fatalf("failed opening file: %s", err)
			}
		}
		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)
		var txtlines []string

		for scanner.Scan() {
			txtlines = append(txtlines, scanner.Text())
		}

		var exit int
		for _, eachline := range txtlines {
			lines := strings.Split(string(eachline), " *")
			if strings.Contains(string(eachline), " *") {
				var h hash.Hash
				if *md == "sha256" {
					h = sha256.New()
				} else if *md == "sha512" {
					h = sha512.New()
				} else if *md == "sha512_256" {
					h = sha512.New512_256()
				} else if *md == "md5" {
					h = md5.New()
				} else if *md == "sha1" {
					h = sha1.New()
				} else if *md == "rmd128" {
					h = ripemd.New128()
				} else if *md == "rmd160" {
					h = ripemd.New160()
				} else if *md == "rmd256" {
					h = ripemd.New256()
				} else if *md == "sha3_256" {
					h = sha3.New256()
				} else if *md == "sha3_512" {
					h = sha3.New512()
				} else if *md == "keccak256" {
					h = sha3.NewLegacyKeccak256()
				} else if *md == "keccak512" {
					h = sha3.NewLegacyKeccak512()
				} else if *md == "whirlpool" {
					h = whirlpool.New()
				} else if *md == "blake256" {
					h = blake256.New()
				} else if *md == "blake512" {
					h = blake512.New()
				} else if *md == "blake2b256" {
					h, _ = blake2b.New256([]byte(*key))
				} else if *md == "blake2b512" {
					h, _ = blake2b.New512([]byte(*key))
				} else if *md == "blake2s256" {
					h, _ = blake2s.New256([]byte(*key))
				} else if *md == "blake2s128" {
					h, _ = blake2s.New128([]byte(*key))
				} else if *md == "groestl" {
					h = groestl.New256()
				} else if *md == "groestl512" {
					h = groestl512.New512()
				} else if *md == "skein256" {
					h = skein256.New256([]byte(*key))
				} else if *md == "skein512_256" {
					h = skein.New256([]byte(*key))
				} else if *md == "skein512" {
					h = skein.New512([]byte(*key))
				} else if *md == "jh" {
					h = jh.New256()
				} else if *md == "tiger" {
					h = tiger.New()
				} else if *md == "tiger128" {
					h = tiger128.New()
				} else if *md == "tiger160" {
					h = tiger160.New()
				} else if *md == "tiger2" {
					h = tiger.New2()
				} else if *md == "tiger2_128" {
					h = tiger128.New2()
				} else if *md == "tiger2_160" {
					h = tiger160.New2()
				} else if *md == "sm3" {
					h = sm3.New()
				} else if *md == "gost94" {
					h = gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
				} else if *md == "streebog256" {
					h = gost34112012256.New()
				} else if *md == "streebog512" {
					h = gost34112012512.New()
				} else if *md == "stribog256" {
					h = gostribog.New256()
				} else if *md == "stribog512" {
					h = gostribog.New512()
				} else if *md == "djb" {
					h = NewDjb32()
				} else if *md == "djba" {
					h = NewDjb32a()
				} else if *md == "elf32" {
					h = NewElf32()
				} else if *md == "sdbm" {
					h = NewSDBM32()
				} else if *md == "siphash" || *md == "siphash128" {
					var xkey [16]byte
					copy(xkey[:], []byte(*key))
					h, _ = siphash.New128(xkey[:])
				} else if *md == "siphash64" {
					var xkey [16]byte
					copy(xkey[:], []byte(*key))
					h, _ = siphash.New64(xkey[:])
				} else if *md == "lsh256" {
					h = lsh256.New()
				} else if *md == "lsh512" {
					h = lsh512.New()
				} else if *md == "lsh512_256" {
					h = lsh512.New256()
				} else if *md == "blake3" {
					h = blake3.New()
				} else if *md == "cubehash" {
					h = cubehash.New()
				} else if *md == "seahash" {
					h = seahash.New()
				} else if *md == "8-bit" {
					h = pearson.New()
				} else if *md == "crc24" {
					h = crc24.New()
				}
				_, err := os.Stat(lines[1])
				if err == nil {
					f, err := os.Open(lines[1])
					if err != nil {
						log.Fatal(err)
					}
					io.Copy(h, f)
					f.Close()

					if hex.EncodeToString(h.Sum(nil)) == lines[0] {
						fmt.Println(lines[1]+"\t", "OK")
					} else {
						fmt.Println(lines[1]+"\t", "FAILED")
						exit = 1
					}
				} else {
					fmt.Println(lines[1]+"\t", "Not found!")
					exit = 1
				}
			}
		}
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "Process took:", elapsed)
		}
		os.Exit(exit)
	}

	if *mac == "poly1305" {
		var err error
		var keyx [32]byte
		copy(keyx[:], []byte(*key))
		h := poly1305.New(&keyx)
		if _, err = io.Copy(h, os.Stdin); err != nil {
			log.Fatal(err)
		}
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Printf("MAC-POLY1305= %s\n", hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "siphash" {
		var xkey [16]byte
		raw, _ := hex.DecodeString(*key)
		copy(xkey[:], raw)
		h, _ := siphash.New128(xkey[:])
		if _, err := io.Copy(h, os.Stdin); err != nil {
			log.Fatal(err)
		}
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Printf("MAC-SIPHASH128= %s\n", hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "siphash64" {
		var xkey [16]byte
		raw, _ := hex.DecodeString(*key)
		copy(xkey[:], raw)
		h, _ := siphash.New64(xkey[:])
		if _, err := io.Copy(h, os.Stdin); err != nil {
			log.Fatal(err)
		}
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Printf("MAC-SIPHASH64= %s\n", hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "chaskey" {
		var keyRaw []byte
		if *key == "" {
			keyRaw = []byte("0000000000000000")
			fmt.Fprintf(os.Stderr, "Key= %s\n", keyRaw)
		} else {
			keyRaw = []byte(*key)
		}
		if len([]byte(keyRaw)) != 16 {
			log.Fatal("CHASKEY's secret key must have 64-bit.")
		}
		xkey := [4]uint32{binary.LittleEndian.Uint32([]byte(keyRaw)[:]),
			binary.LittleEndian.Uint32([]byte(keyRaw)[4:]),
			binary.LittleEndian.Uint32([]byte(keyRaw)[8:]),
			binary.LittleEndian.Uint32([]byte(keyRaw)[12:]),
		}
		var t [32]byte
		h := chaskey.New(xkey)
		line, _ := ioutil.ReadAll(os.Stdin)
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.MAC(line, t[:]))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Printf("MAC-CHASKEY= %s\n", hex.EncodeToString(h.MAC(line, t[:])))
		os.Exit(0)
	}

	if *mac == "hmac" && *md != "poly1305" {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" && (*length == 64 || *length == 128 || *length == 192 || *length == 256) {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "scrypt" && (*length == 64 || *length == 128 || *length == 192 || *length == 256) {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
		} else if *kdf == "hkdf" && (*length == 64 || *length == 128 || *length == 192 || *length == 256) {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
			if len(keyHex) != 128/8 && len(keyHex) != 256/8 && len(keyHex) != 512/8 && len(keyHex) != 1024/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 128-bit. (try \"-bits 128\")")
				os.Exit(1)
			}
		} else {
			keyHex = *key
		}
		key, err := hex.DecodeString(keyHex)
		if err != nil {
			log.Fatal(err)
		}
		h := hmac.New(myHash, key)
		if _, err = io.Copy(h, os.Stdin); err != nil {
			log.Fatal(err)
		}
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Printf("MAC-%s= %s\n", strings.ToUpper(*md), hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	if *mac == "cmac" && (*cph != "hight" && *cph != "blowfish" && *cph != "idea" && *cph != "tea" && *cph != "xtea" && *cph != "rtea" && *cph != "cast5" && *cph != "sm4" && *cph != "skipjack" && *cph != "rc5" && *cph != "3des" && *cph != "simon64" && *cph != "speck64" && *cph != "present" && *cph != "twine" && *cph != "misty1" && *cph != "anubis") {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
			keyHex = hex.EncodeToString(keyRaw)
			if len(keyHex) != 256/8 && len(keyHex) != 512/8 && len(keyHex) != 1024/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 128-bit. (try \"-bits 128\")")
				os.Exit(1)
			}
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
			if len(keyHex) != 256/8 && len(keyHex) != 512/8 && len(keyHex) != 1024/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 128-bit. (try \"-bits 128\")")
				os.Exit(1)
			}
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
			if len(keyHex) != 128/8 && len(keyHex) != 256/8 && len(keyHex) != 512/8 && len(keyHex) != 1024/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 128-bit. (try \"-bits 128\")")
				os.Exit(1)
			}
		} else {
			keyHex = *key
			if len(keyHex) != 256/8 && len(keyHex) != 512/8 && len(keyHex) != 1024/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 128-bit. (try \"-rand -bits 128\")")
				os.Exit(1)
			}
		}
		var ciph cipher.Block
		if *cph == "camellia" {
			ciph, err = camellia.NewCipher([]byte(keyHex))
		} else if *cph == "aes" {
			ciph, err = aes.NewCipher([]byte(keyHex))
		} else if *cph == "serpent" {
			ciph, err = serpent.NewCipher([]byte(keyHex))
		} else if *cph == "twofish" {
			ciph, err = twofish.NewCipher([]byte(keyHex))
		} else if *cph == "seed" {
			ciph, err = seed.NewCipher([]byte(keyHex))
		} else if *cph == "rc6" {
			ciph = rc6.NewCipher([]byte(keyHex))
		} else if *cph == "kuznechik" {
			if len(keyHex) != 256/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 128-bit. (try \"-rand -bits 128\")")
				os.Exit(1)
			}
			ciph = gost3412128.NewCipher([]byte(keyHex))
		} else if *cph == "grasshopper" {
			if len(keyHex) != 256/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 128-bit. (try \"-rand -bits 128\")")
				os.Exit(1)
			}
			ciph, _ = kuznechik.NewCipher([]byte(keyHex))
		} else if *cph == "magma" {
			if len(keyHex) != 256/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 128-bit. (try \"-rand -bits 128\")")
				os.Exit(1)
			}
			ciph = gost341264.NewCipher([]byte(keyHex))
		} else if *cph == "gost89" {
			if len(keyHex) != 256/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 128-bit. (try \"-rand -bits 128\")")
				os.Exit(1)
			}
			ciph = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxIdGostR341194CryptoProParamSet)
		} else if *cph == "threefish" {
			tweak := make([]byte, 16)
			ciph, err = threefish.New256([]byte(keyHex), tweak)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "threefish512" {
			tweak := make([]byte, 16)
			ciph, err = threefish.New512([]byte(keyHex), tweak)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "threefish1024" {
			tweak := make([]byte, 16)
			ciph, err = threefish.New1024([]byte(keyHex), tweak)
			if err != nil {
				log.Fatal(err)
			}
		} else if *cph == "simon128" {
			ciph = simonspeck.NewSimon128([]byte(keyHex))
		} else if *cph == "speck128" {
			ciph = simonspeck.NewSpeck128([]byte(keyHex))
		} else if *cph == "lea" {
			ciph, _ = lea.NewCipher([]byte(keyHex))
		} else if *cph == "aria" {
			ciph, _ = aria.NewCipher([]byte(keyHex))
		} else if *cph == "sealion" {
			ciph, _ = sealion.NewCipher([]byte(keyHex))
		} else if *cph == "seaturtle" {
			ciph, _ = seaturtle.NewCipher([]byte(keyHex))
		}

		if err != nil {
			log.Fatal(err)
		}
		h, _ := cmac.New(ciph)
		io.Copy(h, os.Stdin)
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Printf("MAC-%s= %s\n", strings.ToUpper(*cph), hex.EncodeToString(h.Sum(nil)))
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "Process took:", elapsed)
		}
		os.Exit(0)
	}

	if *mac == "cmac" && (*cph == "hight" || *cph == "anubis" || *cph == "blowfish" || *cph == "idea" || *cph == "cast5" || *cph == "tea" || *cph == "xtea" || *cph == "rtea" || *cph == "sm4" || *cph == "skipjack" || *cph == "rc5" || *cph == "3des" || *cph == "speck64" || *cph == "simon64" || *cph == "present" || *cph == "twine" || *cph == "misty1" && *cph != "threefish") {
		var keyHex string
		var keyRaw []byte
		var lgt string
		var err error
		if *cph == "3des" {
			lgt = "96"
		} else if *cph == "skipjack" {
			lgt = "40"
		} else {
			lgt = "64"
		}
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
			keyHex = hex.EncodeToString(keyRaw)
			if len(keyHex) != 128/8 && len(keyHex) != 80/8 && len(keyHex) != 64/8 && len(keyHex) != 192/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have " + lgt + "-bit. (try \"-bits " + lgt + "\")")
				os.Exit(1)
			}
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
			if len(keyHex) != 128/8 && len(keyHex) != 80/8 && len(keyHex) != 64/8 && len(keyHex) != 192/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have " + lgt + "-bit. (try \"-bits " + lgt + "\")")
				os.Exit(1)
			}
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
			if len(keyHex) != 128/8 && len(keyHex) != 80/8 && len(keyHex) != 64/8 && len(keyHex) != 192/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have " + lgt + "-bit. (try \"-bits " + lgt + "\")")
				os.Exit(1)
			}
		} else {
			keyHex = *key
			if len(keyHex) != 128/8 && len(keyHex) != 80/8 && len(keyHex) != 64/8 && len(keyHex) != 192/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have " + lgt + "-bit. (try \"-rand -bits " + lgt + "\")")
				os.Exit(1)
			}
		}
		var ciph cipher.Block
		if *cph == "blowfish" {
			ciph, err = blowfish.NewCipher([]byte(keyHex))
		} else if *cph == "idea" {
			ciph, _ = idea.NewCipher([]byte(keyHex))
		} else if *cph == "hight" {
			ciph, _ = hight.NewCipher([]byte(keyHex))
		} else if *cph == "tea" {
			ciph, err = tea.NewCipher([]byte(keyHex))
		} else if *cph == "cast5" {
			ciph, _ = cast5.NewCipher([]byte(keyHex))
		} else if *cph == "xtea" {
			ciph, _ = xtea.NewCipher([]byte(keyHex))
		} else if *cph == "rtea" {
			ciph, _ = rtea.NewCipher([]byte(keyHex))
		} else if *cph == "sm4" {
			ciph, _ = sm4.NewCipher([]byte(keyHex))
		} else if *cph == "skipjack" {
			ciph, _ = skipjack.New([]byte(keyHex))
		} else if *cph == "rc5" {
			ciph, _ = rc5.New([]byte(keyHex))
		} else if *cph == "3des" {
			ciph, _ = des.NewTripleDESCipher([]byte(keyHex))
		} else if *cph == "simon64" {
			ciph = simonspeck.NewSimon64([]byte(keyHex))
		} else if *cph == "speck64" {
			ciph = simonspeck.NewSpeck64([]byte(keyHex))
		} else if *cph == "present" {
			ciph, _ = present.NewCipher([]byte(keyHex))
		} else if *cph == "twine" {
			ciph, _ = twine.New([]byte(keyHex))
		} else if *cph == "misty1" {
			ciph, _ = misty1.New([]byte(keyHex))
		} else if *cph == "anubis" {
			ciph = anubis.New([]byte(keyHex))
		}
		if err != nil {
			log.Fatal(err)
		}
		h, _ := cmac.New(ciph)
		io.Copy(h, os.Stdin)
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Printf("MAC-%s= %s\n", strings.ToUpper(*cph), hex.EncodeToString(h.Sum(nil)))
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "Process took:", elapsed)
		}
		os.Exit(0)
	}

	if *mac == "pmac" && *cph != "sm4" && (*cph == "hight" || *cph == "blowfish" || *cph == "idea" || *cph == "cast5" || *cph == "tea" || *cph == "xtea" || *cph == "rtea" || *cph == "skipjack" || *cph == "rc5" || *cph == "3des" || *cph == "speck64" || *cph == "simon64" || *cph == "present" || *cph == "twine" || *cph == "misty1" || *cph == "gost89" || *cph == "magma") {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
			keyHex = hex.EncodeToString(keyRaw)
			if len(keyHex) != 128/8 && len(keyHex) != 256/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 64-bit. (try \"-bits 64\")")
				os.Exit(1)
			}
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
			if len(keyHex) != 128/8 && len(keyHex) != 256/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 64-bit. (try \"-bits 64\")")
				os.Exit(1)
			}
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
			if len(keyHex) != 128/8 && len(keyHex) != 256/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 64-bit. (try \"-bits 64\")")
				os.Exit(1)
			}
		} else if *key == "" {
			keyHex = "0000000000000000"
			fmt.Println("Key=", keyHex)
		} else if *key != "" {
			keyHex = *key
			if len(keyHex) != 128/8 && len(keyHex) != 256/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 64-bit. (try \"-rand -bits 64\")")
				os.Exit(1)
			}
		}
		var ciph cipher.Block
		if *cph == "blowfish" {
			ciph, err = blowfish.NewCipher([]byte(keyHex))
		} else if *cph == "idea" {
			ciph, _ = idea.NewCipher([]byte(keyHex))
		} else if *cph == "hight" {
			ciph, _ = hight.NewCipher([]byte(keyHex))
		} else if *cph == "tea" {
			ciph, err = tea.NewCipher([]byte(keyHex))
		} else if *cph == "cast5" {
			ciph, _ = cast5.NewCipher([]byte(keyHex))
		} else if *cph == "xtea" {
			ciph, _ = xtea.NewCipher([]byte(keyHex))
		} else if *cph == "magma" {
			if len(keyHex) != 256/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 128-bit. (try \"-rand -bits 128\")")
				os.Exit(1)
			}
			ciph = gost341264.NewCipher([]byte(keyHex))
		} else if *cph == "gost89" {
			if len(keyHex) != 256/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 128-bit. (try \"-rand -bits 128\")")
				os.Exit(1)
			}
			ciph = gost28147.NewCipher([]byte(keyHex), &gost28147.SboxIdGostR341194CryptoProParamSet)
		} else if *cph == "rtea" {
			ciph, _ = rtea.NewCipher([]byte(keyHex))
		} else if *cph == "skipjack" {
			ciph, _ = skipjack.New([]byte(keyHex))
		} else if *cph == "rc5" {
			ciph, _ = rc5.New([]byte(keyHex))
		} else if *cph == "3des" {
			ciph, _ = des.NewTripleDESCipher([]byte(keyHex))
		} else if *cph == "simon64" {
			ciph = simonspeck.NewSimon64([]byte(keyHex))
		} else if *cph == "speck64" {
			ciph = simonspeck.NewSpeck64([]byte(keyHex))
		} else if *cph == "present" {
			ciph, _ = present.NewCipher([]byte(keyHex))
		} else if *cph == "twine" {
			ciph, _ = twine.New([]byte(keyHex))
		} else if *cph == "misty1" {
			ciph, _ = misty1.New([]byte(keyHex))
		}
		if err != nil {
			log.Fatal(err)
		}
		h := pmac64.New(ciph)
		io.Copy(h, os.Stdin)
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Printf("MAC-%s= %s\n", strings.ToUpper(*cph), hex.EncodeToString(h.Sum(nil)))
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "Process took:", elapsed)
		}
		os.Exit(0)
	}

	if *mac == "pmac" {
		var keyHex string
		var keyRaw []byte
		var err error
		if *kdf == "pbkdf2" {
			keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
			keyHex = hex.EncodeToString(keyRaw)
			if len(keyHex) != 256/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 128-bit. (try \"-bits 128\")")
				os.Exit(1)
			}
		} else if *kdf == "scrypt" {
			keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
			if err != nil {
				log.Fatal(err)
			}
			keyHex = hex.EncodeToString(keyRaw)
			if len(keyHex) != 256/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 128-bit. (try \"-bits 128\")")
				os.Exit(1)
			}
		} else if *kdf == "hkdf" {
			keyRaw, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
			if err != nil {
				log.Fatal(err)
			}
			keySlice := string(keyRaw[:])
			keyHex = hex.EncodeToString([]byte(keySlice)[:*length/8])
			if len(keyHex) != 256/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 128-bit. (try \"-bits 128\")")
				os.Exit(1)
			}
		} else if *key == "" {
			keyHex = "00000000000000000000000000000000"
			fmt.Println("Key=", keyHex)
		} else if *key != "" {
			keyHex = *key
			if len(keyHex) != 256/8 && len(keyHex) != 128/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 128-bit. (try \"-rand -bits 128\")")
				os.Exit(1)
			}
		}
		var ciph cipher.Block
		if *cph == "camellia" {
			ciph, err = camellia.NewCipher([]byte(keyHex))
		} else if *cph == "aes" {
			ciph, err = aes.NewCipher([]byte(keyHex))
		} else if *cph == "serpent" {
			ciph, err = serpent.NewCipher([]byte(keyHex))
		} else if *cph == "twofish" {
			ciph, err = twofish.NewCipher([]byte(keyHex))
		} else if *cph == "seed" {
			ciph, err = seed.NewCipher([]byte(keyHex))
		} else if *cph == "rc6" {
			ciph = rc6.NewCipher([]byte(keyHex))
		} else if *cph == "kuznechik" {
			ciph = gost3412128.NewCipher([]byte(keyHex))
		} else if *cph == "grasshopper" {
			ciph, _ = kuznechik.NewCipher([]byte(keyHex))
		} else if *cph == "simon128" {
			ciph = simonspeck.NewSimon128([]byte(keyHex))
		} else if *cph == "speck128" {
			ciph = simonspeck.NewSpeck128([]byte(keyHex))
		} else if *cph == "lea" {
			ciph, _ = lea.NewCipher([]byte(keyHex))
		} else if *cph == "aria" {
			ciph, _ = aria.NewCipher([]byte(keyHex))
		} else if *cph == "sealion" {
			ciph, _ = sealion.NewCipher([]byte(keyHex))
		} else if *cph == "seaturtle" {
			ciph, _ = seaturtle.NewCipher([]byte(keyHex))
		} else if *cph == "sm4" {
			if len(keyHex) != 128/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 64-bit. (try \"-rand -bits 64\")")
				os.Exit(1)
			}
			ciph, _ = sm4.NewCipher([]byte(keyHex))
		} else if *cph == "anubis" {
			if len(keyHex) != 128/8 {
				alg := strings.ToUpper(*cph)
				fmt.Println(alg + "'s secret key must have 64-bit. (try \"-rand -bits 64\")")
				os.Exit(1)
			}
			ciph = anubis.New([]byte(keyHex))
		}
		if err != nil {
			log.Fatal(err)
		}
		h := pmac.New(ciph)
		io.Copy(h, os.Stdin)
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Printf("MAC-%s= %s\n", strings.ToUpper(*cph), hex.EncodeToString(h.Sum(nil)))
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "Process took:", elapsed)
		}
		os.Exit(0)
	}

	if *mac == "gost" {
		var keyRaw []byte
		if *key == "" {
			keyRaw = []byte("00000000000000000000000000000000")
			fmt.Fprintf(os.Stderr, "Key= %s\n", keyRaw)
		} else {
			keyRaw = []byte(*key)
		}
		var iv [8]byte
		if *vector == "" {
			fmt.Fprintf(os.Stderr, "IV= %x\n", iv)
		} else {
			raw, err := hex.DecodeString(*vector)
			if err != nil {
				log.Fatal(err)
			}
			iv = *byte8(raw)
			if err != nil {
				log.Fatal(err)
			}
		}
		c := gost28147.NewCipher(keyRaw, &gost28147.SboxIdGostR341194CryptoProParamSet)
		var h *gost28147.MAC
		if *length == 64 {
			h, _ = c.NewMAC(8, iv[:])
		} else {
			h, _ = c.NewMAC(4, iv[:])
		}
		io.Copy(h, os.Stdin)
		var verify bool
		if *sig != "" {
			mac := hex.EncodeToString(h.Sum(nil))
			if mac != *sig {
				verify = false
				fmt.Println(verify)
				os.Exit(1)
			} else {
				verify = true
				fmt.Println(verify)
				os.Exit(0)
			}
		}
		fmt.Printf("MAC-GOST= %s\n", hex.EncodeToString(h.Sum(nil)))
		if *util == "chrono" {
			elapsed := time.Since(start)
			fmt.Fprintln(os.Stderr, "Process took:", elapsed)
		}
		os.Exit(0)
	}

	if *kdf == "pbkdf2" && (*length == 32 || *length == 40 || *length == 64 || *length == 80 || *length == 96 || *length == 128 || *length == 160 || *length == 184 || *length == 192 || *length == 256 || *length == 320 || *length == 512 || *length == 1024) {
		var keyRaw []byte
		keyRaw = pbkdf2.Key([]byte(*key), []byte(*salt), *iter, *length/8, myHash)
		fmt.Println(hex.EncodeToString(keyRaw))
		os.Exit(0)
	} else if *kdf == "scrypt" && (*length == 32 || *length == 40 || *length == 64 || *length == 80 || *length == 96 || *length == 128 || *length == 160 || *length == 184 || *length == 192 || *length == 256 || *length == 320 || *length == 512 || *length == 1024) {
		var keyRaw []byte
		var err error
		keyRaw, err = Key([]byte(*key), []byte(*salt), *iter<<14, 8, 1, *length/8)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(keyRaw))
	} else if *kdf == "hkdf" && (*length == 32 || *length == 40 || *length == 64 || *length == 80 || *length == 96 || *length == 128 || *length == 184 || *length == 192 || *length == 256 || *length == 512 || *length == 1024) {
		hash, err := Hkdf([]byte(*key), []byte(*salt), []byte(*info))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", hash[:*length/8])
	}

	if (*tcpip == "dump" || *tcpip == "send" || *tcpip == "dial" || *tcpip == "listen") && *alg == "sm2" {
		priv, err := sm2.GenerateKey(nil)
		if err != nil {
			log.Fatal(err)
		}
		privPem, err := c509.WritePrivateKeyToPem(priv, nil)
		if err != nil {
			log.Fatal(err)
		}
		pubKey, _ := priv.Public().(*sm2.PublicKey)
		pubkeyPem, err := c509.WritePublicKeyToPem(pubKey)
		privKey, err := c509.ReadPrivateKeyFromPem(privPem, nil)
		if err != nil {
			log.Fatal(err)
		}
		pubKey, err = c509.ReadPublicKeyFromPem(pubkeyPem)
		if err != nil {
			log.Fatal(err)
		}
		templateReq := c509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "test.example.com",
				Organization: []string{"Test"},
			},
		}
		reqPem, err := c509.CreateCertificateRequestToPem(&templateReq, privKey)
		if err != nil {
			log.Fatal(err)
		}
		req, err := c509.ReadCertificateRequestFromPem(reqPem)
		if err != nil {
			log.Fatal(err)
		}
		err = req.CheckSignature()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Request CheckSignature error:%v \n", err)
		} else {
			fmt.Fprintf(os.Stderr, "CheckSignature ok\n")
		}

		consensus := externalip.DefaultConsensus(nil, nil)
		ip, _ := consensus.ExternalIP()

		extraExtensionData := []byte("extra extension")
		template := c509.Certificate{
			SerialNumber: big.NewInt(-1),
			Subject: pkix.Name{
				CommonName: ip.String(),
				ExtraNames: []pkix.AttributeTypeAndValue{
					{
						Type:  []int{2, 5, 4, 42},
						Value: *key,
					},
				},
			},
			NotBefore: time.Now(),
			NotAfter:  time.Date(2021, time.October, 10, 12, 1, 1, 1, time.UTC),

			BasicConstraintsValid: true,
			IsCA:                  true,

			IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

			PolicyIdentifiers: []asn1.ObjectIdentifier{[]int{1, 2, 3}},

			ExtraExtensions: []pkix.Extension{
				{
					Id:    []int{1, 2, 3, 4},
					Value: extraExtensionData,
				},
			},
		}

		pripem, err := c509.WritePrivateKeyToPem(priv, nil)
		if err != nil {
			log.Fatal(err)
		}

		pubKey, _ = priv.Public().(*sm2.PublicKey)
		certpem, err := c509.CreateCertificateToPem(&template, &template, pubKey, privKey)
		if err != nil {
			log.Fatal("failed to create cert file")
		}

		if *tcpip == "dump" {
			cert, err := gmtls.X509KeyPair(certpem, pripem)

			if err != nil {
				log.Fatal(err)
			}
			config := gmtls.Config{Certificates: []gmtls.Certificate{cert}, ClientAuth: gmtls.RequireAnyClientCert}
			config.Rand = rand.Reader

			port := "8081"
			if *public != "" {
				port = *public
			}

			ln, err := gmtls.Listen("tcp", ":"+port, &config)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Fprintln(os.Stderr, "Server(TLS) up and listening on port "+port)

			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Println(err)
					continue
				}
				go handleConnection(conn)

				var buf bytes.Buffer
				io.Copy(&buf, conn)
				text := strings.TrimSuffix(string(buf.Bytes()), "\n")
				fmt.Println(text)
				os.Exit(0)
			}
		}

		if *tcpip == "listen" {
			cert, err := gmtls.X509KeyPair(certpem, pripem)

			if err != nil {
				log.Fatal(err)
			}
			config := gmtls.Config{Certificates: []gmtls.Certificate{cert}, ClientAuth: gmtls.RequireAnyClientCert}
			config.Rand = rand.Reader

			port := "8081"
			if *public != "" {
				port = *public
			}

			ln, err := gmtls.Listen("tcp", ":"+port, &config)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Fprintln(os.Stderr, "Server(TLS) up and listening on port "+port)

			conn, err := ln.Accept()
			if err != nil {
				log.Println(err)
			}
			defer ln.Close()

			fmt.Println("Connection accepted")

			for {
				message, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Print("Received: ", string(message))

				newmessage := strings.ToUpper(message)
				conn.Write([]byte(newmessage + "\n"))
			}
		}

		if *tcpip == "send" {
			cert, err := gmtls.X509KeyPair(certpem, pripem)

			if err != nil {
				log.Fatal(err)
			}

			ipport := "127.0.0.1:8081"
			if *public != "" {
				ipport = *public
			}

			log.Printf("Connecting to %s\n", ipport)

			config := gmtls.Config{Certificates: []gmtls.Certificate{cert}, InsecureSkipVerify: true}
			conn, err := gmtls.Dial("tcp", ipport, &config)

			if err != nil {
				log.Fatal(err)
			}

			buf := bytes.NewBuffer(nil)
			scanner := os.Stdin
			io.Copy(buf, scanner)

			text := string(buf.Bytes())
			fmt.Fprintf(conn, text)

			defer conn.Close()

			log.Printf("Connection established between %s and localhost.\n", conn.RemoteAddr().String())
			os.Exit(0)
		}

		if *tcpip == "dial" {
			cert, err := gmtls.X509KeyPair(certpem, pripem)

			if err != nil {
				log.Fatal(err)
			}

			ipport := "127.0.0.1:8081"
			if *public != "" {
				ipport = *public
			}

			config := gmtls.Config{Certificates: []gmtls.Certificate{cert}, InsecureSkipVerify: true}
			conn, err := gmtls.Dial("tcp", ipport, &config)
			if err != nil {
				log.Fatal(err)
			}
			certs := conn.ConnectionState().PeerCertificates
			for _, cert := range certs {
				fmt.Printf("Issuer Name: %s\n", cert.Issuer)
				fmt.Printf("Expiry: %s \n", cert.NotAfter.Format("Monday, 02-Jan-06 15:04:05 MST"))
				fmt.Printf("Common Name: %s \n", cert.Issuer.CommonName)
				fmt.Printf("IP Address: %s \n", cert.IPAddresses)
			}
			if err != nil {
				log.Fatal(err)
			}
			defer conn.Close()

			for {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Text to be sent: ")
				text, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Fprintf(conn, text+"\n")

				message, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Print("Server response: " + message)
			}
		}
	}

	if (*tcpip == "dump" || *tcpip == "send" || *tcpip == "listen" || *tcpip == "dial") && (*alg == "ecdsa" || *alg == "rsa" || *alg == "RSA" || *alg == "ed25519" || *alg == "sm2" || *alg == "sm2p256v1") {
		var priv interface{}
		var err error
		if *alg == "ed25519" {
			_, priv, err = ed25519.GenerateKey(rand.Reader)
		} else if *alg == "ecdsa" || *alg == "secp256r1" || *alg == "prime256v1" {
			priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		} else if *alg == "rsa" || *alg == "RSA" {
			priv, err = rsa.GenerateKey(rand.Reader, 2048)
		}

		if err != nil {
			log.Fatalf("Failed to generate private key: %v", err)
		}

		keyUsage := x509.KeyUsageDigitalSignature

		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			log.Fatalf("Failed to generate serial number: %v", err)
		}

		consensus := externalip.DefaultConsensus(nil, nil)
		ip, _ := consensus.ExternalIP()

		Mins := 1
		NotAfter := time.Now().Local().Add(time.Minute * time.Duration(Mins))

		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName: ip.String(),
			},
			NotBefore: time.Now(),
			NotAfter:  NotAfter,

			KeyUsage:              keyUsage,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			IsCA:                  true,

			PermittedDNSDomainsCritical: true,
			DNSNames:                    []string{ip.String()},
			IPAddresses:                 []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
		}

		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign

		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
		if err != nil {
			log.Fatalf("Failed to create certificate: %v", err)
		}

		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			log.Fatalf("Unable to marshal private key: %v", err)
		}
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

		if *tcpip == "dump" {
			cert, err := tls.X509KeyPair(certPEM, privPEM)

			if err != nil {
				log.Fatal(err)
			}
			config := tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert}
			config.Rand = rand.Reader

			port := "8081"
			if *public != "" {
				port = *public
			}

			ln, err := tls.Listen("tcp", ":"+port, &config)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Fprintln(os.Stderr, "Server(TLS) up and listening on port "+port)

			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Println(err)
					continue
				}
				go handleConnection(conn)

				var buf bytes.Buffer
				io.Copy(&buf, conn)
				text := strings.TrimSuffix(string(buf.Bytes()), "\n")
				fmt.Println(text)
				os.Exit(0)
			}
		}

		if *tcpip == "listen" {
			cert, err := tls.X509KeyPair(certPEM, privPEM)
			cfg := tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert}
			cfg.Rand = rand.Reader

			port := "8081"
			if *public != "" {
				port = *public
			}

			ln, err := tls.Listen("tcp", ":"+port, &cfg)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Fprintln(os.Stderr, "Server(TLS) up and listening on port "+port)

			conn, err := ln.Accept()
			if err != nil {
				log.Println(err)
			}
			defer ln.Close()

			fmt.Println("Connection accepted")

			for {
				message, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Print("Received: ", string(message))

				newmessage := strings.ToUpper(message)
				conn.Write([]byte(newmessage + "\n"))
			}
		}

		if *tcpip == "send" {
			cert, err := tls.X509KeyPair(certPEM, privPEM)

			if err != nil {
				log.Fatal(err)
			}

			ipport := "127.0.0.1:8081"
			if *public != "" {
				ipport = *public
			}

			log.Printf("Connecting to %s\n", ipport)

			config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
			conn, err := tls.Dial("tcp", ipport, &config)

			certs := conn.ConnectionState().PeerCertificates
			for _, cert := range certs {
				fmt.Printf("Expiry: %s \n", cert.NotAfter.Format("2006-01-02T15:04:05"))
				fmt.Printf("Common Name: %s \n", cert.Issuer.CommonName)
			}

			if err != nil {
				log.Fatal(err)
			}

			buf := bytes.NewBuffer(nil)
			scanner := os.Stdin
			io.Copy(buf, scanner)

			text := string(buf.Bytes())
			fmt.Fprintf(conn, text)

			defer conn.Close()

			log.Printf("Connection established between %s and localhost.\n", conn.RemoteAddr().String())
			os.Exit(0)
		}

		if *tcpip == "dial" {
			cert, err := tls.X509KeyPair(certPEM, privPEM)
			cfg := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

			ipport := "127.0.0.1:8081"
			if *public != "" {
				ipport = *public
			}

			conn, err := tls.Dial("tcp", ipport, &cfg)
			if err != nil {
				log.Fatal(err)
			}
			certs := conn.ConnectionState().PeerCertificates
			for _, cert := range certs {
				fmt.Printf("Issuer Name: %s\n", cert.Issuer)
				fmt.Printf("Expiry: %s \n", cert.NotAfter.Format("Monday, 02-Jan-06 15:04:05 MST"))
				fmt.Printf("Common Name: %s \n", cert.Issuer.CommonName)
				fmt.Printf("IP Address: %s \n", cert.IPAddresses)
			}
			if err != nil {
				log.Fatal(err)
			}
			defer conn.Close()

			for {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Text to be sent: ")
				text, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Fprintf(conn, text+"\n")

				message, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					fmt.Println(err)
					os.Exit(3)
				}
				fmt.Print("Server response: " + message)
			}
		}
		os.Exit(0)
	}

	if *tcpip == "ip" {
		consensus := externalip.DefaultConsensus(nil, nil)
		ip, _ := consensus.ExternalIP()
		fmt.Println(ip.String())
		os.Exit(0)
	}

	if *pkeyutl == "INIParsePrivate" {
		ini, _ := simpleini.Parse(os.Stdin)
		str, _ := ini.GetString(*info, "Private")

		fmt.Printf("%s\n", str)
		os.Exit(0)
	}

	if *pkeyutl == "INIParsePublic" {
		ini, _ := simpleini.Parse(os.Stdin)
		str, _ := ini.GetString(*info, "Public")

		fmt.Printf("%s\n", str)
		os.Exit(0)
	}

	if *pkeyutl == "INIParseShared" {
		ini, _ := simpleini.Parse(os.Stdin)
		str, _ := ini.GetString(*info, "Shared")

		fmt.Printf("%s\n", str)
		os.Exit(0)
	}

	if *del != "" {
		shredder := shred.Shredder{}
		shredconf := shred.NewShredderConf(&shredder, shred.WriteZeros|shred.WriteRand, *iter, true)
		matches, err := filepath.Glob(*del)
		if err != nil {
			log.Fatal(err)
		}

		for _, match := range matches {
			err := shredconf.ShredDir(match)
			if err != nil {
				log.Fatal(err)
			}
		}
		os.Exit(0)
	}

	if *pkeyutl == "text" && (*alg == "brainpool256r1" || *alg == "brainpool256t1" || *alg == "brainpool512r1" || *alg == "brainpool512t1" || *alg == "ecdsa" || *alg == "ECDSA" || *alg == "secp256r1" || *alg == "prime256v1" || *alg == "sm2" || *alg == "brainpool160t1" || *alg == "secp160r1" || *alg == "secp160k1" || *alg == "secp160r2" || *alg == "secp128r1" || *alg == "secp112r1" || *alg == "wtls8" || *alg == "wtls9" || *alg == "numsp256d1" || *alg == "numsp512d1" || *alg == "oakley256" || *alg == "frp256v1" || *alg == "prime192v1" || *alg == "secp192r1" || *alg == "secp192k1" || *alg == "secp256k1" || *alg == "prime192v2" || *alg == "prime192v3" || *alg == "brainpool192t1" || *alg == "oakley192" || *alg == "sm2p256v1" || *alg == "sm9p256v1" || *alg == "ecgost2001" || *alg == "ecgost2001A" || *alg == "ecgost2001B" || *alg == "ecgost2001C" || *alg == "ecgost2012" || *alg == "ecgost2012A" || *alg == "ecgost2012B" || *alg == "wapip192v1" || *alg == "fp256bn" || *alg == "fp512bn") && (*alg != "ed25519" && *alg != "X25519" && *alg != "gost2012" && *alg != "gost2001") {

		var pubkeyCurve elliptic.Curve
		if *alg == "brainpool256" || *alg == "brainpool256r1" {
			pubkeyCurve = brainpool.P256r1()
		} else if *alg == "brainpool256t1" {
			pubkeyCurve = brainpool.P256t1()
		} else if *alg == "brainpool512" || *alg == "brainpool512r1" {
			pubkeyCurve = brainpool.P512r1()
		} else if *alg == "brainpool512t1" {
			pubkeyCurve = brainpool.P512t1()
		} else if *alg == "ecdsa" || *alg == "secp256r1" || *alg == "prime256v1" {
			pubkeyCurve = elliptic.P256()
		} else if *alg == "sm2" {
			pubkeyCurve = sm2.P256Sm2()
		} else if *alg == "secp160r1" {
			pubkeyCurve = secp160r1.P160()
		} else if *alg == "secp160r2" {
			pubkeyCurve = secp160r2.P160()
		} else if *alg == "secp160k1" {
			pubkeyCurve = koblitz.S160()
		} else if *alg == "secp192k1" {
			pubkeyCurve = koblitz.S192()
		} else if *alg == "secp256k1" {
			pubkeyCurve = koblitz.S256()
		} else if *alg == "brainpool192t1" {
			pubkeyCurve = gocurves.Bp192()
		} else if *alg == "brainpool160t1" {
			pubkeyCurve = gocurves.Bp160()
		} else if *alg == "secp128r1" {
			pubkeyCurve = secp128r1.Secp128r1()
		} else if *alg == "secp112r1" {
			pubkeyCurve = secp112r1.P112()
		} else if *alg == "numsp256d1" {
			pubkeyCurve = gocurves.Nums256()
		} else if *alg == "numsp512d1" {
			pubkeyCurve = gocurves.Nums512()
		} else if *alg == "oakley256" {
			pubkeyCurve = oakley256.Oakley256()
		} else if *alg == "frp256v1" {
			pubkeyCurve = frp256v1.FRP256v1()
		} else if *alg == "oakley192" {
			pubkeyCurve = oakley192.Oakley192()
		} else if *alg == "prime192v1" || *alg == "secp192r1" {
			pubkeyCurve = prime192.Prime192v1()
		} else if *alg == "prime192v2" {
			pubkeyCurve = prime192.Prime192v2()
		} else if *alg == "prime192v3" {
			pubkeyCurve = prime192.Prime192v3()
		} else if *alg == "wapip192v1" {
			pubkeyCurve = wapip192v1.P192()
		} else if *alg == "sm2p256v1" {
			pubkeyCurve = sm2p256v1.P256()
		} else if *alg == "sm9p256v1" {
			pubkeyCurve = sm9p256v1.P256()
		} else if *alg == "ecgost2001" || *alg == "ecgost2001A" {
			pubkeyCurve = gost2001.GOST2001A()
		} else if *alg == "ecgost2001B" {
			pubkeyCurve = gost2001.GOST2001B()
		} else if *alg == "ecgost2001C" {
			pubkeyCurve = gost2001.GOST2001C()
		} else if *alg == "ecgost2012" || *alg == "ecgost2012A" {
			pubkeyCurve = gost2012.TC26512A()
		} else if *alg == "ecgost2012B" {
			pubkeyCurve = gost2012.TC26512B()
		} else if *alg == "fp256bn" {
			pubkeyCurve = bn.P256()
		} else if *alg == "fp512bn" {
			pubkeyCurve = bn.P512()
		} else if *alg == "wtls8" {
			pubkeyCurve = wtls.P112()
		} else if *alg == "wtls9" {
			pubkeyCurve = wtls.P160()
		}

		if *key == "-" {
			data, _ := ioutil.ReadAll(os.Stdin)
			b := strings.TrimSuffix(string(data), "\r\n")
			b = strings.TrimSuffix(b, "\n")
			privatekey, _ := ReadPrivateKeyFromHex(b)
			pubkey := privatekey.PublicKey
			fmt.Println("Private Key:")

			fmt.Println(" D:", privatekey.D)
			print(" ", len(WritePrivateKeyToHex(privatekey))/2, " bytes ", len(WritePrivateKeyToHex(privatekey))*4, " bits\n")
			splitx := SplitSubN(WritePrivateKeyToHex(privatekey), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitx), "[]"), 60) {
				fmt.Printf("  %-10s  \n", strings.ToUpper(chunk))
			}
			fmt.Println("Public Key:")
			fmt.Println(" X:", pubkey.X)
			fmt.Println(" Y:", pubkey.Y)

			print(" ", len(WritePublicKeyToHex(&pubkey))/2, " bytes ", len(WritePublicKeyToHex(&pubkey))*4, " bits\n")
			splitz := SplitSubN(WritePublicKeyToHex(&pubkey), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 60) {
				fmt.Printf("  %-10s  \n", strings.ToUpper(chunk))
			}
			fmt.Println("OID:", strings.ToUpper(*alg))
		} else if *key != "-" {
			privatekey, _ := ReadPrivateKeyFromHex(*key)
			pubkey := privatekey.PublicKey
			fmt.Println("Private Key:")

			fmt.Println(" D:", privatekey.D)
			print(" ", len(WritePrivateKeyToHex(privatekey))/2, " bytes ", len(WritePrivateKeyToHex(privatekey))*4, " bits\n")
			splitx := SplitSubN(WritePrivateKeyToHex(privatekey), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitx), "[]"), 60) {
				fmt.Printf("  %-10s  \n", strings.ToUpper(chunk))
			}

			fmt.Println("Public Key:")
			fmt.Println(" X:", pubkey.X)
			fmt.Println(" Y:", pubkey.Y)
			print(" ", len(WritePublicKeyToHex(&pubkey))/2, " bytes ", len(WritePublicKeyToHex(&pubkey))*4, " bits\n")
			splitz := SplitSubN(WritePublicKeyToHex(&pubkey), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 60) {
				fmt.Printf("  %-10s  \n", strings.ToUpper(chunk))
			}
			fmt.Println("OID:", strings.ToUpper(*alg))
			if validateECPublicKey(pubkeyCurve, pubkey.X, pubkey.Y) {
				os.Exit(0)
			} else {
				os.Exit(1)
			}
		}
	} else if *pkeyutl == "text" && (*alg == "gost2001" || *alg == "gost2001A" || *alg == "gost2001B" || *alg == "gost2001C" || *alg == "gost2001XA" || *alg == "gost2001XB" || *alg == "gost2012_256" || *alg == "gost2012_256A" || *alg == "gost2012_256B" || *alg == "gost2012_256C" || *alg == "gost2012_256D" || *alg == "gost2012_512" || *alg == "gost2012_512A" || *alg == "gost2012_512B" || *alg == "gost2012_512C") {
		var curve *gost3410.Curve
		if *alg == "gost2001" || *alg == "gost2001A" {
			curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()
		} else if *alg == "gost2001B" {
			curve = gost3410.CurveIdGostR34102001CryptoProBParamSet()
		} else if *alg == "gost2001C" {
			curve = gost3410.CurveIdGostR34102001CryptoProCParamSet()
		} else if *alg == "gost2001XA" {
			curve = gost3410.CurveIdGostR34102001CryptoProXchAParamSet()
		} else if *alg == "gost2001XB" {
			curve = gost3410.CurveIdGostR34102001CryptoProXchBParamSet()
		} else if *alg == "gost2012_256" || *alg == "gost2012_256A" {
			curve = gost3410.CurveIdtc26gost34102012256paramSetA()
		} else if *alg == "gost2012_256B" {
			curve = gost3410.CurveIdtc26gost34102012256paramSetB()
		} else if *alg == "gost2012_256C" {
			curve = gost3410.CurveIdtc26gost34102012256paramSetC()
		} else if *alg == "gost2012_256D" {
			curve = gost3410.CurveIdtc26gost34102012256paramSetD()
		} else if *alg == "gost2012_512" || *alg == "gost2012_512A" {
			curve = gost3410.CurveIdtc26gost341012512paramSetA()
		} else if *alg == "gost2012_512B" {
			curve = gost3410.CurveIdtc26gost341012512paramSetB()
		} else if *alg == "gost2012_512C" {
			curve = gost3410.CurveIdtc26gost34102012512paramSetC()
		}
		if *key == "-" {
			data, _ := ioutil.ReadAll(os.Stdin)
			b := strings.TrimSuffix(string(data), "\r\n")
			b = strings.TrimSuffix(b, "\n")
			prvRaw, err := hex.DecodeString(b)
			if err != nil {
				log.Fatal(err)
			}
			privatekey, err := gost3410.NewPrivateKey(curve, prvRaw)
			if err != nil {
				log.Fatal(err)
			}

			pubkey, err := privatekey.PublicKey()
			if err != nil {
				log.Fatal(err)
			}
			pubRaw := pubkey.Raw()

			fmt.Println("Private Key:")
			fmt.Println(" K:", strings.ToUpper(hex.EncodeToString(prvRaw)))
			print(" ", len(hex.EncodeToString(prvRaw))/2, " bytes ", len(hex.EncodeToString(prvRaw))*4, " bits\n")
			splitx := SplitSubN(hex.EncodeToString(prvRaw), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitx), "[]"), 60) {
				fmt.Printf("  %-10s  \n", strings.ToUpper(chunk))
			}
			fmt.Println("Public Key:")
			fmt.Println(" X:", pubkey.X)
			fmt.Println(" Y:", pubkey.Y)

			print(" ", len(hex.EncodeToString(pubRaw))/2, " bytes ", len(hex.EncodeToString(pubRaw))*4, " bits\n")
			splitz := SplitSubN(hex.EncodeToString(pubRaw), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 60) {
				fmt.Printf("  %-10s  \n", strings.ToUpper(chunk))
			}
			fmt.Println("OID:", strings.ToUpper(*alg))
		} else if *key != "-" {
			prvRaw, err := hex.DecodeString(*key)
			if err != nil {
				log.Fatal(err)
			}
			privatekey, err := gost3410.NewPrivateKey(curve, prvRaw)
			if err != nil {
				log.Fatal(err)
			}
			pubkey, err := privatekey.PublicKey()
			if err != nil {
				log.Fatal(err)
			}
			pubRaw := pubkey.Raw()

			fmt.Println("Private Key:")

			fmt.Println(" K:", strings.ToUpper(hex.EncodeToString(prvRaw)))
			print(" ", len(*key)/2, " bytes ", len(*key)*4, " bits\n")
			splitx := SplitSubN(*key, 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitx), "[]"), 60) {
				fmt.Printf("  %-10s  \n", strings.ToUpper(chunk))
			}
			fmt.Println("Public Key:")
			fmt.Println(" X:", pubkey.X)
			fmt.Println(" Y:", pubkey.Y)
			print(" ", len(hex.EncodeToString(pubRaw))/2, " bytes ", len(hex.EncodeToString(pubRaw))*4, " bits\n")
			splitz := SplitSubN(hex.EncodeToString(pubRaw), 2)
			for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 60) {
				fmt.Printf("  %-10s  \n", strings.ToUpper(chunk))
			}
			fmt.Println("OID:", strings.ToUpper(*alg))
		}
	}

	if *util == "fingerprint" && *key == "-" {
		fmt.Println(randomart.FromFile(os.Stdin))
	} else if *util == "fingerprint" && *key != "-" {
		fmt.Println(randomart.FromString(*key))
	}
}

func Verify(data, signature []byte, pubkey *ecdsa.PublicKey) bool {
	var h hash.Hash
	if *md == "sha256" {
		h = sha256.New()
	} else if *md == "sha512" {
		h = sha512.New()
	} else if *md == "sha512_256" {
		h = sha512.New512_256()
	} else if *md == "sha1" {
		h = sha1.New()
	} else if *md == "rmd128" {
		h = ripemd.New128()
	} else if *md == "rmd160" {
		h = ripemd.New160()
	} else if *md == "rmd256" {
		h = ripemd.New256()
	} else if *md == "sha3_256" {
		h = sha3.New256()
	} else if *md == "sha3_512" {
		h = sha3.New512()
	} else if *md == "keccak256" {
		h = sha3.NewLegacyKeccak256()
	} else if *md == "keccak512" {
		h = sha3.NewLegacyKeccak512()
	} else if *md == "whirlpool" {
		h = whirlpool.New()
	} else if *md == "blake256" {
		h = blake256.New()
	} else if *md == "blake512" {
		h = blake512.New()
	} else if *md == "blake2b256" {
		h, _ = blake2b.New256(nil)
	} else if *md == "blake2b512" {
		h, _ = blake2b.New512(nil)
	} else if *md == "blake2s256" {
		h, _ = blake2s.New256(nil)
	} else if *md == "groestl" {
		h = groestl.New256()
	} else if *md == "groestl512" {
		h = groestl512.New512()
	} else if *md == "skein256" {
		h = skein256.New256(nil)
	} else if *md == "skein512_256" {
		h = skein.New256(nil)
	} else if *md == "skein512" {
		h = skein.New512(nil)
	} else if *md == "jh" {
		h = jh.New256()
	} else if *md == "tiger" {
		h = tiger.New()
	} else if *md == "tiger128" {
		h = tiger128.New()
	} else if *md == "tiger160" {
		h = tiger160.New()
	} else if *md == "tiger2" {
		h = tiger.New2()
	} else if *md == "tiger2_128" {
		h = tiger128.New2()
	} else if *md == "tiger2_160" {
		h = tiger160.New2()
	} else if *md == "sm3" {
		h = sm3.New()
	} else if *md == "gost94" {
		h = gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
	} else if *md == "streebog256" {
		h = gost34112012256.New()
	} else if *md == "streebog512" {
		h = gost34112012512.New()
	} else if *md == "stribog256" {
		h = gostribog.New256()
	} else if *md == "stribog512" {
		h = gostribog.New512()
	} else if *md == "lsh256" {
		h = lsh256.New()
	} else if *md == "lsh512" {
		h = lsh512.New()
	} else if *md == "lsh512_256" {
		h = lsh512.New256()
	} else if *md == "blake3" {
		h = blake3.New()
	} else if *md == "cubehash" {
		h = cubehash.New()
	}
	digest := h.Sum(data)

	curveOrderByteSize := pubkey.Curve.Params().P.BitLen() / 8

	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature[:curveOrderByteSize])
	s.SetBytes(signature[curveOrderByteSize:])

	return ecdsa.Verify(pubkey, digest[:], r, s)
}

func Sign(data []byte, privkey *ecdsa.PrivateKey) ([]byte, error) {
	var h hash.Hash
	if *md == "sha256" {
		h = sha256.New()
	} else if *md == "sha512" {
		h = sha512.New()
	} else if *md == "sha512_256" {
		h = sha512.New512_256()
	} else if *md == "sha1" {
		h = sha1.New()
	} else if *md == "rmd128" {
		h = ripemd.New128()
	} else if *md == "rmd160" {
		h = ripemd.New160()
	} else if *md == "rmd256" {
		h = ripemd.New256()
	} else if *md == "sha3_256" {
		h = sha3.New256()
	} else if *md == "sha3_512" {
		h = sha3.New512()
	} else if *md == "keccak256" {
		h = sha3.NewLegacyKeccak256()
	} else if *md == "keccak512" {
		h = sha3.NewLegacyKeccak512()
	} else if *md == "whirlpool" {
		h = whirlpool.New()
	} else if *md == "blake256" {
		h = blake256.New()
	} else if *md == "blake512" {
		h = blake512.New()
	} else if *md == "blake2b256" {
		h, _ = blake2b.New256(nil)
	} else if *md == "blake2b512" {
		h, _ = blake2b.New512(nil)
	} else if *md == "blake2s256" {
		h, _ = blake2s.New256(nil)
	} else if *md == "groestl" {
		h = groestl.New256()
	} else if *md == "groestl512" {
		h = groestl512.New512()
	} else if *md == "skein256" {
		h = skein256.New256(nil)
	} else if *md == "skein512_256" {
		h = skein.New256(nil)
	} else if *md == "skein512" {
		h = skein.New512(nil)
	} else if *md == "jh" {
		h = jh.New256()
	} else if *md == "tiger" {
		h = tiger.New()
	} else if *md == "tiger128" {
		h = tiger128.New()
	} else if *md == "tiger160" {
		h = tiger160.New()
	} else if *md == "tiger2" {
		h = tiger.New2()
	} else if *md == "tiger2_128" {
		h = tiger128.New2()
	} else if *md == "tiger2_160" {
		h = tiger160.New2()
	} else if *md == "sm3" {
		h = sm3.New()
	} else if *md == "gost94" {
		h = gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
	} else if *md == "streebog256" {
		h = gost34112012256.New()
	} else if *md == "streebog512" {
		h = gost34112012512.New()
	} else if *md == "stribog256" {
		h = gostribog.New256()
	} else if *md == "stribog512" {
		h = gostribog.New512()
	} else if *md == "lsh256" {
		h = lsh256.New()
	} else if *md == "lsh512" {
		h = lsh512.New()
	} else if *md == "lsh512_256" {
		h = lsh512.New256()
	} else if *md == "blake3" {
		h = blake3.New()
	} else if *md == "cubehash" {
		h = cubehash.New()
	}
	digest := h.Sum(data)

	r, s, err := ecdsa.Sign(rand.Reader, privkey, digest[:])
	if err != nil {
		return nil, err
	}

	params := privkey.Curve.Params()
	curveOrderByteSize := params.P.BitLen() / 8
	rBytes, sBytes := r.Bytes(), s.Bytes()
	signature := make([]byte, curveOrderByteSize*2)
	copy(signature[curveOrderByteSize-len(rBytes):], rBytes)
	copy(signature[curveOrderByteSize*2-len(sBytes):], sBytes)

	return signature, nil
}

func ReadPrivateKeyFromHex(Dhex string) (*ecdsa.PrivateKey, error) {
	var c elliptic.Curve
	if *alg == "brainpool256r1" {
		c = brainpool.P256r1()
	} else if *alg == "brainpool256t1" {
		c = brainpool.P256t1()
	} else if *alg == "brainpool512r1" {
		c = brainpool.P512r1()
	} else if *alg == "brainpool512t1" {
		c = brainpool.P512t1()
	} else if *alg == "ecdsa" || *alg == "secp256r1" || *alg == "prime256v1" {
		c = elliptic.P256()
	} else if *alg == "sm2" {
		c = sm2.P256Sm2()
	} else if *alg == "secp160r1" {
		c = secp160r1.P160()
	} else if *alg == "secp160r2" {
		c = secp160r2.P160()
	} else if *alg == "secp160k1" {
		c = koblitz.S160()
	} else if *alg == "secp192k1" {
		c = koblitz.S192()
	} else if *alg == "secp256k1" {
		c = koblitz.S256()
	} else if *alg == "brainpool160t1" {
		c = gocurves.Bp160()
	} else if *alg == "brainpool192t1" {
		c = gocurves.Bp192()
	} else if *alg == "secp128r1" {
		c = secp128r1.Secp128r1()
	} else if *alg == "secp112r1" {
		c = secp112r1.P112()
	} else if *alg == "numsp256d1" {
		c = gocurves.Nums256()
	} else if *alg == "numsp512d1" {
		c = gocurves.Nums512()
	} else if *alg == "oakley256" {
		c = oakley256.Oakley256()
	} else if *alg == "frp256v1" {
		c = frp256v1.FRP256v1()
	} else if *alg == "oakley192" {
		c = oakley192.Oakley192()
	} else if *alg == "prime192v1" || *alg == "secp192r1" {
		c = prime192.Prime192v1()
	} else if *alg == "prime192v2" {
		c = prime192.Prime192v2()
	} else if *alg == "prime192v3" {
		c = prime192.Prime192v3()
	} else if *alg == "sm2p256v1" {
		c = sm2p256v1.P256()
	} else if *alg == "sm9p256v1" {
		c = sm9p256v1.P256()
	} else if *alg == "wapip192v1" {
		c = wapip192v1.P192()
	} else if *alg == "ecgost2001" || *alg == "ecgost2001A" {
		c = gost2001.GOST2001A()
	} else if *alg == "ecgost2001B" {
		c = gost2001.GOST2001B()
	} else if *alg == "ecgost2001C" {
		c = gost2001.GOST2001C()
	} else if *alg == "ecgost2012" || *alg == "ecgost2012A" {
		c = gost2012.TC26512A()
	} else if *alg == "ecgost2012B" {
		c = gost2012.TC26512B()
	} else if *alg == "fp256bn" {
		c = bn.P256()
	} else if *alg == "fp512bn" {
		c = bn.P512()
	} else if *alg == "wtls8" {
		c = wtls.P112()
	} else if *alg == "wtls9" {
		c = wtls.P160()
	}
	d, err := hex.DecodeString(Dhex)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).SetBytes(d)
	params := c.Params()
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(params.N, one)
	if k.Cmp(n) >= 0 {
		return nil, errors.New("privateKey's D is overflow.")
	}
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func ReadPrivateKeyFromHex160(Dhex string) (*eccrypt160.PrivateKey, error) {
	var c elliptic.Curve
	if *alg == "secp160r1" {
		c = secp160r1.P160()
	} else if *alg == "secp160r2" {
		c = secp160r2.P160()
	} else if *alg == "secp160k1" {
		c = koblitz.S160()
	} else if *alg == "brainpool160t1" {
		c = gocurves.Bp160()
	} else if *alg == "wtls9" {
		c = wtls.P160()
	}
	d, err := hex.DecodeString(Dhex)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).SetBytes(d)
	params := c.Params()
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(params.N, one)
	if k.Cmp(n) >= 0 {
		return nil, errors.New("privateKey's D is overflow.")
	}
	priv := new(eccrypt160.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func ReadPrivateKeyFromHex192(Dhex string) (*eccrypt192.PrivateKey, error) {
	var c elliptic.Curve
	if *alg == "secp192k1" {
		c = koblitz.S192()
	} else if *alg == "brainpool192t1" {
		c = gocurves.Bp192()
	} else if *alg == "oakley192" {
		c = oakley192.Oakley192()
	} else if *alg == "prime192v1" || *alg == "secp192r1" {
		c = prime192.Prime192v1()
	} else if *alg == "prime192v2" {
		c = prime192.Prime192v2()
	} else if *alg == "prime192v3" {
		c = prime192.Prime192v3()
	} else if *alg == "wapip192v1" {
		c = wapip192v1.P192()
	}

	d, err := hex.DecodeString(Dhex)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).SetBytes(d)
	params := c.Params()
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(params.N, one)
	if k.Cmp(n) >= 0 {
		return nil, errors.New("privateKey's D is overflow.")
	}
	priv := new(eccrypt192.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func ReadPrivateKeyFromHex256(Dhex string) (*eccrypt.PrivateKey, error) {
	var c elliptic.Curve
	if *alg == "brainpool256r1" {
		c = brainpool.P256r1()
	} else if *alg == "brainpool256t1" {
		c = brainpool.P256t1()
	} else if *alg == "ecdsa" || *alg == "secp256r1" || *alg == "prime256v1" {
		c = elliptic.P256()
	} else if *alg == "secp256k1" {
		c = koblitz.S256()
	} else if *alg == "sm2" {
		c = sm2.P256Sm2()
	} else if *alg == "oakley256" {
		c = oakley256.Oakley256()
	} else if *alg == "frp256v1" {
		c = frp256v1.FRP256v1()
	} else if *alg == "sm2p256v1" {
		c = sm2p256v1.P256()
	} else if *alg == "sm9p256v1" {
		c = sm9p256v1.P256()
	} else if *alg == "ecgost2001" || *alg == "ecgost2001A" {
		c = gost2001.GOST2001A()
	} else if *alg == "ecgost2001B" {
		c = gost2001.GOST2001B()
	} else if *alg == "ecgost2001C" {
		c = gost2001.GOST2001C()
	} else if *alg == "fp256bn" {
		c = bn.P256()
	}
	d, err := hex.DecodeString(Dhex)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).SetBytes(d)
	params := c.Params()
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(params.N, one)
	if k.Cmp(n) >= 0 {
		return nil, errors.New("privateKey's D is overflow.")
	}
	priv := new(eccrypt.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func ReadPrivateKeyFromHex512(Dhex string) (*eccrypt512.PrivateKey, error) {
	var c elliptic.Curve
	if *alg == "brainpool512r1" {
		c = brainpool.P512r1()
	} else if *alg == "brainpool512t1" {
		c = brainpool.P512t1()
	} else if *alg == "numsp512d1" {
		c = gocurves.Nums512()
	} else if *alg == "numsp512t1" {
		c = gocurves.Nums512t1()
	} else if *alg == "ecgost2012" || *alg == "ecgost2012A" {
		c = gost2012.TC26512A()
	} else if *alg == "ecgost2012B" {
		c = gost2012.TC26512B()
	} else if *alg == "fp512bn" {
		c = bn.P512()
	}
	d, err := hex.DecodeString(Dhex)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).SetBytes(d)
	params := c.Params()
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(params.N, one)
	if k.Cmp(n) >= 0 {
		return nil, errors.New("privateKey's D is overflow.")
	}
	priv := new(eccrypt512.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func WritePrivateKeyToHex(key *ecdsa.PrivateKey) string {
	d := key.D.Bytes()
	if *alg == "brainpool256r1" || *alg == "brainpool256t1" || *alg == "sm2" || *alg == "ecdsa" || *alg == "secp256r1" || *alg == "prime256v1" || *alg == "numsp256d1" || *alg == "frp256v1" || *alg == "oakley256" || *alg == "fp256bn" {
		if n := len(d); n < 32 {
			d = append(zeroByteSlice()[:32-n], d...)
		}
	} else if *alg == "brainpool512r1" || *alg == "brainpool512t1" || *alg == "numsp512d1" || *alg == "numsp512t1" || *alg == "fp512bn" {
		if n := len(d); n < 64 {
			d = append(zeroByteSlice()[:32-n], d...)
		}
	} else if *alg == "brainpool192t1" || *alg == "secp192r1" || *alg == "prime192v1" || *alg == "prime192v2" || *alg == "prime192v3" || *alg == "oakley192" {
		if n := len(d); n < 24 {
			d = append(zeroByteSlice()[:24-n], d...)
		}
	} else if *alg == "brainpool160t1" || *alg == "secp160r1" || *alg == "secp160r2" || *alg == "secp160k1" || *alg == "wtls9" {
		if n := len(d); n < 20 {
			d = append(zeroByteSlice()[:20-n], d...)
		}
	} else if *alg == "secp128r1" {
		if n := len(d); n < 16 {
			d = append(zeroByteSlice()[:16-n], d...)
		}
	} else if *alg == "secp112r1" || *alg == "wtls8" {
		if n := len(d); n < 14 {
			d = append(zeroByteSlice()[:14-n], d...)
		}
	}
	c := []byte{}
	c = append(c, d...)
	return hex.EncodeToString(c)
}

func ReadPublicKeyFromHex(Qhex string) (*ecdsa.PublicKey, error) {
	q, err := hex.DecodeString(Qhex)
	if err != nil {
		return nil, err
	}

	if *alg == "brainpool256r1" || *alg == "brainpool256t1" || *alg == "sm2" || *alg == "ecdsa" || *alg == "secp256r1" || *alg == "prime256v1" || *alg == "secp256k1" || *alg == "numsp256d1" || *alg == "frp256v1" || *alg == "oakley256" || *alg == "fp256bn" {
		if len(q) == 65 || q[0] == byte(0x04) {
			q = q[1:]
		}
		if len(q) != 64 {
			return nil, errors.New("publicKey is not uncompressed.")
		}
	} else if *alg == "brainpool512r1" || *alg == "brainpool512t1" || *alg == "numsp512t1" || *alg == "numsp512d1" || *alg == "fp512bn" {
		if len(q) == 129 || q[0] == byte(0x04) {
			q = q[1:]
		}
		if len(q) != 128 {
			return nil, errors.New("publicKey is not uncompressed.")
		}
	} else if *alg == "brainpool192t1" || *alg == "secp192r1" || *alg == "secp192k1" || *alg == "prime192v1" || *alg == "prime192v2" || *alg == "prime192v3" || *alg == "oakley192" {
		if len(q) == 49 || q[0] == byte(0x04) {
			q = q[1:]
		}
		if len(q) != 48 {
			return nil, errors.New("publicKey is not uncompressed.")
		}
	} else if *alg == "brainpool160t1" || *alg == "secp160r1" || *alg == "secp160r2" || *alg == "secp160k1" || *alg == "wtls9" {
		if len(q) == 41 || q[0] == byte(0x04) {
			q = q[1:]
		}
		if len(q) != 40 {
			return nil, errors.New("publicKey is not uncompressed.")
		}
	} else if *alg == "secp128r1" {
		if len(q) == 33 || q[0] == byte(0x04) {
			q = q[1:]
		}
		if len(q) != 32 {
			return nil, errors.New("publicKey is not uncompressed.")
		}
	} else if *alg == "secp112r1" || *alg == "wtls8" {
		if len(q) == 29 || q[0] == byte(0x04) {
			q = q[1:]
		}
		if len(q) != 28 {
			return nil, errors.New("publicKey is not uncompressed.")
		}
	}

	pub := new(ecdsa.PublicKey)
	if *alg == "brainpool256r1" {
		pub.Curve = brainpool.P256r1()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "brainpool256t1" {
		pub.Curve = brainpool.P256t1()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "brainpool512r1" {
		pub.Curve = brainpool.P512r1()
		pub.X = new(big.Int).SetBytes(q[:64])
		pub.Y = new(big.Int).SetBytes(q[64:])
	} else if *alg == "brainpool512t1" {
		pub.Curve = brainpool.P512t1()
		pub.X = new(big.Int).SetBytes(q[:64])
		pub.Y = new(big.Int).SetBytes(q[64:])
	} else if *alg == "ecdsa" || *alg == "secp256r1" || *alg == "prime256v1" {
		pub.Curve = elliptic.P256()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "secp256k1" {
		pub.Curve = koblitz.S256()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "sm2" {
		pub.Curve = sm2.P256Sm2()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "brainpool160t1" {
		pub.Curve = gocurves.Bp160()
		pub.X = new(big.Int).SetBytes(q[:20])
		pub.Y = new(big.Int).SetBytes(q[20:])
	} else if *alg == "brainpool192t1" {
		pub.Curve = gocurves.Bp192()
		pub.X = new(big.Int).SetBytes(q[:24])
		pub.Y = new(big.Int).SetBytes(q[24:])
	} else if *alg == "secp160r1" {
		pub.Curve = secp160r1.P160()
		pub.X = new(big.Int).SetBytes(q[:20])
		pub.Y = new(big.Int).SetBytes(q[20:])
	} else if *alg == "secp160r2" {
		pub.Curve = secp160r2.P160()
		pub.X = new(big.Int).SetBytes(q[:20])
		pub.Y = new(big.Int).SetBytes(q[20:])
	} else if *alg == "secp160k1" {
		pub.Curve = koblitz.S160()
		pub.X = new(big.Int).SetBytes(q[:20])
		pub.Y = new(big.Int).SetBytes(q[20:])
	} else if *alg == "secp192k1" {
		pub.Curve = koblitz.S192()
		pub.X = new(big.Int).SetBytes(q[:24])
		pub.Y = new(big.Int).SetBytes(q[24:])
	} else if *alg == "secp128r1" {
		pub.Curve = secp128r1.Secp128r1()
		pub.X = new(big.Int).SetBytes(q[:16])
		pub.Y = new(big.Int).SetBytes(q[16:])
	} else if *alg == "secp112r1" {
		pub.Curve = secp112r1.P112()
		pub.X = new(big.Int).SetBytes(q[:14])
		pub.Y = new(big.Int).SetBytes(q[14:])
	} else if *alg == "numsp256d1" {
		pub.Curve = gocurves.Nums256()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "numsp512d1" {
		pub.Curve = gocurves.Nums512()
		pub.X = new(big.Int).SetBytes(q[:64])
		pub.Y = new(big.Int).SetBytes(q[64:])
	} else if *alg == "oakley256" {
		pub.Curve = oakley256.Oakley256()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "frp256v1" {
		pub.Curve = frp256v1.FRP256v1()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "secp192r1" || *alg == "prime192v1" {
		pub.Curve = prime192.Prime192v1()
		pub.X = new(big.Int).SetBytes(q[:24])
		pub.Y = new(big.Int).SetBytes(q[24:])
	} else if *alg == "prime192v2" {
		pub.Curve = prime192.Prime192v2()
		pub.X = new(big.Int).SetBytes(q[:24])
		pub.Y = new(big.Int).SetBytes(q[24:])
	} else if *alg == "prime192v3" {
		pub.Curve = prime192.Prime192v3()
		pub.X = new(big.Int).SetBytes(q[:24])
		pub.Y = new(big.Int).SetBytes(q[24:])
	} else if *alg == "oakley192" {
		pub.Curve = oakley192.Oakley192()
		pub.X = new(big.Int).SetBytes(q[:24])
		pub.Y = new(big.Int).SetBytes(q[24:])
	} else if *alg == "sm2p256v1" {
		pub.Curve = sm2p256v1.P256()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "sm9p256v1" {
		pub.Curve = sm9p256v1.P256()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "wapip192v1" {
		pub.Curve = wapip192v1.P192()
		pub.X = new(big.Int).SetBytes(q[:24])
		pub.Y = new(big.Int).SetBytes(q[24:])
	} else if *alg == "ecgost2001" || *alg == "ecgost2001A" {
		pub.Curve = gost2001.GOST2001A()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "ecgost2001B" {
		pub.Curve = gost2001.GOST2001B()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "ecgost2001C" {
		pub.Curve = gost2001.GOST2001C()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "ecgost2012" || *alg == "ecgost2012A" {
		pub.Curve = gost2012.TC26512A()
		pub.X = new(big.Int).SetBytes(q[:64])
		pub.Y = new(big.Int).SetBytes(q[64:])
	} else if *alg == "ecgost2012B" {
		pub.Curve = gost2012.TC26512B()
		pub.X = new(big.Int).SetBytes(q[:64])
		pub.Y = new(big.Int).SetBytes(q[64:])
	} else if *alg == "fp256bn" {
		pub.Curve = bn.P256()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "fp512bn" {
		pub.Curve = bn.P512()
		pub.X = new(big.Int).SetBytes(q[:64])
		pub.Y = new(big.Int).SetBytes(q[64:])
	} else if *alg == "wtls8" {
		pub.Curve = wtls.P112()
		pub.X = new(big.Int).SetBytes(q[:14])
		pub.Y = new(big.Int).SetBytes(q[14:])
	} else if *alg == "wtls9" {
		pub.Curve = wtls.P160()
		pub.X = new(big.Int).SetBytes(q[:20])
		pub.Y = new(big.Int).SetBytes(q[20:])
	}
	return pub, nil
}

func ReadPublicKeyFromHex160(Qhex string) (*eccrypt160.PublicKey, error) {
	q, err := hex.DecodeString(Qhex)
	if err != nil {
		return nil, err
	}
	if len(q) == 41 || q[0] == byte(0x04) {
		q = q[1:]
	}
	if len(q) != 40 {
		return nil, errors.New("publicKey is not uncompressed.")
	}

	pub := new(eccrypt160.PublicKey)
	if *alg == "brainpool160t1" {
		pub.Curve = gocurves.Bp160()
		pub.X = new(big.Int).SetBytes(q[:20])
		pub.Y = new(big.Int).SetBytes(q[20:])
	} else if *alg == "secp160r1" {
		pub.Curve = secp160r1.P160()
		pub.X = new(big.Int).SetBytes(q[:20])
		pub.Y = new(big.Int).SetBytes(q[20:])
	} else if *alg == "secp160r2" {
		pub.Curve = secp160r2.P160()
		pub.X = new(big.Int).SetBytes(q[:20])
		pub.Y = new(big.Int).SetBytes(q[20:])
	} else if *alg == "secp160k1" {
		pub.Curve = koblitz.S160()
		pub.X = new(big.Int).SetBytes(q[:20])
		pub.Y = new(big.Int).SetBytes(q[20:])
	} else if *alg == "wtls9" {
		pub.Curve = wtls.P160()
		pub.X = new(big.Int).SetBytes(q[:20])
		pub.Y = new(big.Int).SetBytes(q[20:])
	}

	return pub, nil
}

func ReadPublicKeyFromHex192(Qhex string) (*eccrypt192.PublicKey, error) {
	q, err := hex.DecodeString(Qhex)
	if err != nil {
		return nil, err
	}
	if len(q) == 49 || q[0] == byte(0x04) {
		q = q[1:]
	}
	if len(q) != 48 {
		return nil, errors.New("publicKey is not uncompressed.")
	}

	pub := new(eccrypt192.PublicKey)
	if *alg == "brainpool192t1" {
		pub.Curve = gocurves.Bp192()
		pub.X = new(big.Int).SetBytes(q[:24])
		pub.Y = new(big.Int).SetBytes(q[24:])
	} else if *alg == "secp192k1" {
		pub.Curve = koblitz.S192()
		pub.X = new(big.Int).SetBytes(q[:24])
		pub.Y = new(big.Int).SetBytes(q[24:])
	} else if *alg == "secp192r1" || *alg == "prime192v1" {
		pub.Curve = prime192.Prime192v1()
		pub.X = new(big.Int).SetBytes(q[:24])
		pub.Y = new(big.Int).SetBytes(q[24:])
	} else if *alg == "prime192v2" {
		pub.Curve = prime192.Prime192v2()
		pub.X = new(big.Int).SetBytes(q[:24])
		pub.Y = new(big.Int).SetBytes(q[24:])
	} else if *alg == "prime192v3" {
		pub.Curve = prime192.Prime192v3()
		pub.X = new(big.Int).SetBytes(q[:24])
		pub.Y = new(big.Int).SetBytes(q[24:])
	} else if *alg == "oakley192" {
		pub.Curve = oakley192.Oakley192()
		pub.X = new(big.Int).SetBytes(q[:24])
		pub.Y = new(big.Int).SetBytes(q[24:])
	} else if *alg == "wapip192v1" {
		pub.Curve = wapip192v1.P192()
		pub.X = new(big.Int).SetBytes(q[:24])
		pub.Y = new(big.Int).SetBytes(q[24:])
	}

	return pub, nil
}

func ReadPublicKeyFromHex256(Qhex string) (*eccrypt.PublicKey, error) {
	q, err := hex.DecodeString(Qhex)
	if err != nil {
		return nil, err
	}
	if len(q) == 65 || q[0] == byte(0x04) {
		q = q[1:]
	}
	if len(q) != 64 {
		return nil, errors.New("publicKey is not uncompressed.")
	}

	pub := new(eccrypt.PublicKey)
	if *alg == "brainpool256r1" {
		pub.Curve = brainpool.P256r1()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "brainpool256t1" {
		pub.Curve = brainpool.P256t1()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "fp256bn" {
		pub.Curve = bn.P256()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "ecdsa" || *alg == "secp256r1" || *alg == "prime256v1" {
		pub.Curve = elliptic.P256()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "secp256k1" {
		pub.Curve = koblitz.S256()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "sm2" {
		pub.Curve = sm2.P256Sm2()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "numsp256d1" {
		pub.Curve = gocurves.Nums256()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "oakley256" {
		pub.Curve = oakley256.Oakley256()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "frp256v1" {
		pub.Curve = frp256v1.FRP256v1()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "sm2p256v1" {
		pub.Curve = sm2p256v1.P256()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "sm9p256v1" {
		pub.Curve = sm9p256v1.P256()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "ecgost2001" || *alg == "ecgost2001A" {
		pub.Curve = gost2001.GOST2001A()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "ecgost2001B" {
		pub.Curve = gost2001.GOST2001B()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	} else if *alg == "ecgost2001C" {
		pub.Curve = gost2001.GOST2001C()
		pub.X = new(big.Int).SetBytes(q[:32])
		pub.Y = new(big.Int).SetBytes(q[32:])
	}

	return pub, nil
}

func ReadPublicKeyFromHex512(Qhex string) (*eccrypt512.PublicKey, error) {
	q, err := hex.DecodeString(Qhex)
	if err != nil {
		return nil, err
	}
	if len(q) == 123 || q[0] == byte(0x04) {
		q = q[1:]
	}
	if len(q) != 128 {
		return nil, errors.New("publicKey is not uncompressed.")
	}

	pub := new(eccrypt512.PublicKey)
	if *alg == "brainpool512r1" {
		pub.Curve = brainpool.P512r1()
		pub.X = new(big.Int).SetBytes(q[:64])
		pub.Y = new(big.Int).SetBytes(q[64:])
	} else if *alg == "brainpool512t1" {
		pub.Curve = brainpool.P512t1()
		pub.X = new(big.Int).SetBytes(q[:64])
		pub.Y = new(big.Int).SetBytes(q[64:])
	} else if *alg == "fp512bn" {
		pub.Curve = bn.P512()
		pub.X = new(big.Int).SetBytes(q[:64])
		pub.Y = new(big.Int).SetBytes(q[64:])
	} else if *alg == "numsp512d1" {
		pub.Curve = gocurves.Nums512()
		pub.X = new(big.Int).SetBytes(q[:64])
		pub.Y = new(big.Int).SetBytes(q[64:])
	} else if *alg == "numsp512t1" {
		pub.Curve = gocurves.Nums512t1()
		pub.X = new(big.Int).SetBytes(q[:64])
		pub.Y = new(big.Int).SetBytes(q[64:])
	} else if *alg == "ecgost2012" || *alg == "ecgost2012A" {
		pub.Curve = gost2012.TC26512A()
		pub.X = new(big.Int).SetBytes(q[:64])
		pub.Y = new(big.Int).SetBytes(q[64:])
	} else if *alg == "ecgost2012B" {
		pub.Curve = gost2012.TC26512B()
		pub.X = new(big.Int).SetBytes(q[:64])
		pub.Y = new(big.Int).SetBytes(q[64:])
	}

	return pub, nil
}

func WritePublicKeyToHex(key *ecdsa.PublicKey) string {
	x := key.X.Bytes()
	y := key.Y.Bytes()
	if *alg == "brainpool256r1" || *alg == "brainpool256t1" || *alg == "sm2" || *alg == "ecdsa" || *alg == "secp256r1" || *alg == "prime256v1" || *alg == "secp256k1" || *alg == "numsp256d1" || *alg == "frp256v1" || *alg == "oakley256" || *alg == "fp256bn" {
		if n := len(x); n < 32 {
			x = append(zeroByteSlice()[:32-n], x...)
		}
		if n := len(y); n < 32 {
			y = append(zeroByteSlice()[:32-n], y...)
		}
	}
	if *alg == "brainpool512r1" || *alg == "brainpool512t1" || *alg == "numsp512d1" || *alg == "numsp512t1" || *alg == "fp512bn" {
		if n := len(x); n < 64 {
			x = append(zeroByteSlice()[:64-n], x...)
		}
		if n := len(y); n < 64 {
			y = append(zeroByteSlice()[:64-n], y...)
		}
	}
	if *alg == "brainpool192t1" || *alg == "prime192v1" || *alg == "prime192v2" || *alg == "prime192v3" || *alg == "secp192r1" || *alg == "oakley192" {
		if n := len(x); n < 24 {
			x = append(zeroByteSlice()[:24-n], x...)
		}
		if n := len(y); n < 24 {
			y = append(zeroByteSlice()[:24-n], y...)
		}
	}
	if *alg == "brainpool160t1" || *alg == "secp160r1" || *alg == "secp160r2" || *alg == "secp160k1" || *alg == "wtls9" {
		if n := len(x); n < 20 {
			x = append(zeroByteSlice()[:20-n], x...)
		}
		if n := len(y); n < 20 {
			y = append(zeroByteSlice()[:20-n], y...)
		}
	}
	if *alg == "secp128r1" {
		if n := len(x); n < 16 {
			x = append(zeroByteSlice()[:16-n], x...)
		}
		if n := len(y); n < 16 {
			y = append(zeroByteSlice()[:16-n], y...)
		}
	}
	if *alg == "secp112r1" || *alg == "wtls8" {
		if n := len(x); n < 14 {
			x = append(zeroByteSlice()[:14-n], x...)
		}
		if n := len(y); n < 14 {
			y = append(zeroByteSlice()[:14-n], y...)
		}
	}
	c := []byte{}
	c = append(c, x...)
	c = append(c, y...)
	return hex.EncodeToString(c)
}

func ReadSM2PrivateKeyFromHex(Dhex string) (*sm2.PrivateKey, error) {
	c := sm2.P256Sm2()
	d, err := hex.DecodeString(Dhex)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).SetBytes(d)
	params := c.Params()
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(params.N, one)
	if k.Cmp(n) >= 0 {
		return nil, errors.New("privateKey's D is overflow.")
	}
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func ReadSM2PublicKeyFromHex(Qhex string) (*sm2.PublicKey, error) {
	q, err := hex.DecodeString(Qhex)
	if err != nil {
		return nil, err
	}
	if len(q) == 65 && q[0] == byte(0x04) {
		q = q[1:]
	}
	if len(q) != 64 {
		return nil, errors.New("publicKey is not uncompressed.")
	}
	pub := new(sm2.PublicKey)
	pub.Curve = sm2.P256Sm2()
	pub.X = new(big.Int).SetBytes(q[:32])
	pub.Y = new(big.Int).SetBytes(q[32:])
	return pub, nil
}

func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}

func GenerateKey() (privateKey *[32]byte, publicKey *[32]byte, err error) {
	var pub, priv [32]byte

	_, err = io.ReadFull(rand.Reader, priv[:])
	if err != nil {
		return nil, nil, err
	}

	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(&pub, &priv)

	return &priv, &pub, nil
}

func GenerateSharedSecret(priv, pub [32]byte) []byte {
	var secret [32]byte

	curve25519.ScalarMult(&secret, &priv, &pub)

	return secret[:]
}

type djb2StringHash32 uint32

func NewDjb32() hash.Hash32                 { sh := djb2StringHash32(0); sh.Reset(); return &sh }
func (sh *djb2StringHash32) Size() int      { return 4 }
func (sh *djb2StringHash32) BlockSize() int { return 1 }
func (sh *djb2StringHash32) Sum32() uint32  { return uint32(*sh) }
func (sh *djb2StringHash32) Reset()         { *sh = djb2StringHash32(5381) }
func (sh *djb2StringHash32) Sum(b []byte) []byte {
	v := uint32(*sh)
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func (sh *djb2StringHash32) Write(b []byte) (int, error) {
	h := uint32(*sh)
	for _, c := range b {
		h = 33*h + uint32(c)
	}
	*sh = djb2StringHash32(h)
	return len(b), nil
}

type djb2aStringHash32 uint32

func NewDjb32a() hash.Hash32                 { sh := djb2aStringHash32(0); sh.Reset(); return &sh }
func (sh *djb2aStringHash32) Size() int      { return 4 }
func (sh *djb2aStringHash32) BlockSize() int { return 1 }
func (sh *djb2aStringHash32) Sum32() uint32  { return uint32(*sh) }
func (sh *djb2aStringHash32) Reset()         { *sh = djb2aStringHash32(5381) }
func (sh *djb2aStringHash32) Sum(b []byte) []byte {
	v := uint32(*sh)
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func (sh *djb2aStringHash32) Write(b []byte) (int, error) {
	h := uint32(*sh)
	for _, c := range b {
		h = 33*h ^ uint32(c)
	}
	*sh = djb2aStringHash32(h)
	return len(b), nil
}

type sdbmStringHash32 uint32

func NewSDBM32() hash.Hash32                { sh := sdbmStringHash32(0); sh.Reset(); return &sh }
func (sh *sdbmStringHash32) Size() int      { return 4 }
func (sh *sdbmStringHash32) BlockSize() int { return 1 }
func (sh *sdbmStringHash32) Sum32() uint32  { return uint32(*sh) }
func (sh *sdbmStringHash32) Reset()         { *sh = sdbmStringHash32(0) }
func (sh *sdbmStringHash32) Sum(b []byte) []byte {
	v := uint32(*sh)
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func (sh *sdbmStringHash32) Write(b []byte) (int, error) {
	h := uint32(*sh)
	for _, c := range b {
		h = uint32(c) + (h << 6) + (h << 16) - h
	}
	*sh = sdbmStringHash32(h)
	return len(b), nil
}

type elf32StringHash32 uint32

func NewElf32() hash.Hash32                  { sh := elf32StringHash32(0); sh.Reset(); return &sh }
func (sh *elf32StringHash32) Size() int      { return 4 }
func (sh *elf32StringHash32) BlockSize() int { return 1 }
func (sh *elf32StringHash32) Sum32() uint32  { return uint32(*sh) }
func (sh *elf32StringHash32) Reset()         { *sh = elf32StringHash32(0) }
func (sh *elf32StringHash32) Sum(b []byte) []byte {
	v := uint32(*sh)
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func (sh *elf32StringHash32) Write(b []byte) (int, error) {
	h := uint32(*sh)
	for _, c := range b {
		h = (h << 4) + uint32(c)
		g := h & 0xf0000000
		if g != 0 {
			h ^= g >> 24
			h &= ^g
		}
	}
	*sh = elf32StringHash32(h)
	return len(b), nil
}

func byte32(s []byte) (a *[32]byte) {
	if len(a) <= len(s) {
		a = (*[len(a)]byte)(unsafe.Pointer(&s[0]))
	}
	return a
}

func byte16(s []byte) (a *[16]byte) {
	if len(a) <= len(s) {
		a = (*[len(a)]byte)(unsafe.Pointer(&s[0]))
	}
	return a
}

func byte10(s []byte) (a *[10]byte) {
	if len(a) <= len(s) {
		a = (*[len(a)]byte)(unsafe.Pointer(&s[0]))
	}
	return a
}

func byte8(s []byte) (a *[8]byte) {
	if len(a) <= len(s) {
		a = (*[len(a)]byte)(unsafe.Pointer(&s[0]))
	}
	return a
}

func Hkdf(master, salt, info []byte) ([128]byte, error) {
	var myHash func() hash.Hash
	if *md == "sha256" {
		myHash = sha256.New
	} else if *md == "sha512" {
		myHash = sha512.New
	} else if *md == "sha512_256" {
		myHash = sha512.New512_256
	} else if *md == "md5" {
		myHash = md5.New
	} else if *md == "sha1" {
		myHash = sha1.New
	} else if *md == "rmd128" {
		myHash = ripemd.New128
	} else if *md == "rmd160" {
		myHash = ripemd.New160
	} else if *md == "rmd256" {
		myHash = ripemd.New256
	} else if *md == "sha3_256" {
		myHash = sha3.New256
	} else if *md == "sha3_512" {
		myHash = sha3.New512
	} else if *md == "keccak256" {
		myHash = sha3.NewLegacyKeccak256
	} else if *md == "keccak512" {
		myHash = sha3.NewLegacyKeccak512
	} else if *md == "whirlpool" {
		myHash = whirlpool.New
	} else if *md == "blake256" {
		myHash = blake256.New
	} else if *md == "blake512" {
		myHash = blake512.New
	} else if *md == "blake2b256" {
		myHash = crypto.BLAKE2b_256.New
	} else if *md == "blake2b512" {
		myHash = crypto.BLAKE2b_512.New
	} else if *md == "blake2s256" {
		myHash = crypto.BLAKE2s_256.New
	} else if *md == "skein256" {
		g := func() hash.Hash {
			return skein256.New256(nil)
		}
		myHash = g
	} else if *md == "skein512_256" {
		g := func() hash.Hash {
			return skein.New256(nil)
		}
		myHash = g
	} else if *md == "skein512" {
		g := func() hash.Hash {
			return skein.New512(nil)
		}
		myHash = g
	} else if *md == "groestl" {
		myHash = groestl.New256
	} else if *md == "groestl512" {
		myHash = groestl512.New512
	} else if *md == "jh" {
		fmt.Fprint(os.Stderr, "JH not supported.")
		os.Exit(1)
	} else if *md == "tiger" {
		myHash = tiger.New
	} else if *md == "tiger128" {
		myHash = tiger128.New
	} else if *md == "tiger160" {
		myHash = tiger160.New
	} else if *md == "tiger2" {
		myHash = tiger.New2
	} else if *md == "tiger2_128" {
		myHash = tiger128.New2
	} else if *md == "tiger2_160" {
		myHash = tiger160.New2
	} else if *md == "sm3" {
		myHash = sm3.New
	} else if *md == "gost94" {
		g := func() hash.Hash {
			return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		}
		myHash = g
	} else if *md == "streebog256" {
		myHash = gost34112012256.New
	} else if *md == "streebog512" {
		myHash = gost34112012512.New
	} else if *md == "stribog256" {
		myHash = gostribog.New256
	} else if *md == "stribog512" {
		myHash = gostribog.New512
	} else if *md == "lsh256" {
		myHash = lsh256.New
	} else if *md == "lsh512" {
		myHash = lsh512.New
	} else if *md == "lsh512_256" {
		myHash = lsh512.New256
	} else if *md == "blake3" {
		g := func() hash.Hash {
			return blake3.New()
		}
		myHash = g
	} else if *md == "cubehash" {
		myHash = cubehash.New
	}
	hkdf := hkdf.New(myHash, master, salt, info)

	key := make([]byte, *length/8)
	_, err := io.ReadFull(hkdf, key)

	var result [128]byte
	copy(result[:], key)

	return result, err
}

func XOR(input, key string) (output string) {
	for i := 0; i < len(input); i++ {
		output += string(input[i] ^ key[i%len(key)])
	}

	return output
}

func CountDigits(i int) (count int) {
	for i != 0 {
		i /= 10
		count = count + 1
	}
	return count
}

func split(s string, size int) []string {
	ss := make([]string, 0, len(s)/size+1)
	for len(s) > 0 {
		if len(s) < size {
			size = len(s)
		}
		ss, s = append(ss, s[:size]), s[size:]

	}
	return ss
}

const maxInt = int(^uint(0) >> 1)

func blockCopy(dst, src []uint32, n int) {
	copy(dst, src[:n])
}

func blockXOR(dst, src []uint32, n int) {
	for i, v := range src[:n] {
		dst[i] ^= v
	}
}

func salsaXOR(tmp *[16]uint32, in, out []uint32) {
	w0 := tmp[0] ^ in[0]
	w1 := tmp[1] ^ in[1]
	w2 := tmp[2] ^ in[2]
	w3 := tmp[3] ^ in[3]
	w4 := tmp[4] ^ in[4]
	w5 := tmp[5] ^ in[5]
	w6 := tmp[6] ^ in[6]
	w7 := tmp[7] ^ in[7]
	w8 := tmp[8] ^ in[8]
	w9 := tmp[9] ^ in[9]
	w10 := tmp[10] ^ in[10]
	w11 := tmp[11] ^ in[11]
	w12 := tmp[12] ^ in[12]
	w13 := tmp[13] ^ in[13]
	w14 := tmp[14] ^ in[14]
	w15 := tmp[15] ^ in[15]

	x0, x1, x2, x3, x4, x5, x6, x7, x8 := w0, w1, w2, w3, w4, w5, w6, w7, w8
	x9, x10, x11, x12, x13, x14, x15 := w9, w10, w11, w12, w13, w14, w15

	for i := 0; i < 8; i += 2 {
		x4 ^= bits.RotateLeft32(x0+x12, 7)
		x8 ^= bits.RotateLeft32(x4+x0, 9)
		x12 ^= bits.RotateLeft32(x8+x4, 13)
		x0 ^= bits.RotateLeft32(x12+x8, 18)

		x9 ^= bits.RotateLeft32(x5+x1, 7)
		x13 ^= bits.RotateLeft32(x9+x5, 9)
		x1 ^= bits.RotateLeft32(x13+x9, 13)
		x5 ^= bits.RotateLeft32(x1+x13, 18)

		x14 ^= bits.RotateLeft32(x10+x6, 7)
		x2 ^= bits.RotateLeft32(x14+x10, 9)
		x6 ^= bits.RotateLeft32(x2+x14, 13)
		x10 ^= bits.RotateLeft32(x6+x2, 18)

		x3 ^= bits.RotateLeft32(x15+x11, 7)
		x7 ^= bits.RotateLeft32(x3+x15, 9)
		x11 ^= bits.RotateLeft32(x7+x3, 13)
		x15 ^= bits.RotateLeft32(x11+x7, 18)

		x1 ^= bits.RotateLeft32(x0+x3, 7)
		x2 ^= bits.RotateLeft32(x1+x0, 9)
		x3 ^= bits.RotateLeft32(x2+x1, 13)
		x0 ^= bits.RotateLeft32(x3+x2, 18)

		x6 ^= bits.RotateLeft32(x5+x4, 7)
		x7 ^= bits.RotateLeft32(x6+x5, 9)
		x4 ^= bits.RotateLeft32(x7+x6, 13)
		x5 ^= bits.RotateLeft32(x4+x7, 18)

		x11 ^= bits.RotateLeft32(x10+x9, 7)
		x8 ^= bits.RotateLeft32(x11+x10, 9)
		x9 ^= bits.RotateLeft32(x8+x11, 13)
		x10 ^= bits.RotateLeft32(x9+x8, 18)

		x12 ^= bits.RotateLeft32(x15+x14, 7)
		x13 ^= bits.RotateLeft32(x12+x15, 9)
		x14 ^= bits.RotateLeft32(x13+x12, 13)
		x15 ^= bits.RotateLeft32(x14+x13, 18)
	}
	x0 += w0
	x1 += w1
	x2 += w2
	x3 += w3
	x4 += w4
	x5 += w5
	x6 += w6
	x7 += w7
	x8 += w8
	x9 += w9
	x10 += w10
	x11 += w11
	x12 += w12
	x13 += w13
	x14 += w14
	x15 += w15

	out[0], tmp[0] = x0, x0
	out[1], tmp[1] = x1, x1
	out[2], tmp[2] = x2, x2
	out[3], tmp[3] = x3, x3
	out[4], tmp[4] = x4, x4
	out[5], tmp[5] = x5, x5
	out[6], tmp[6] = x6, x6
	out[7], tmp[7] = x7, x7
	out[8], tmp[8] = x8, x8
	out[9], tmp[9] = x9, x9
	out[10], tmp[10] = x10, x10
	out[11], tmp[11] = x11, x11
	out[12], tmp[12] = x12, x12
	out[13], tmp[13] = x13, x13
	out[14], tmp[14] = x14, x14
	out[15], tmp[15] = x15, x15
}

func blockMix(tmp *[16]uint32, in, out []uint32, r int) {
	blockCopy(tmp[:], in[(2*r-1)*16:], 16)
	for i := 0; i < 2*r; i += 2 {
		salsaXOR(tmp, in[i*16:], out[i*8:])
		salsaXOR(tmp, in[i*16+16:], out[i*8+r*16:])
	}
}

func integer(b []uint32, r int) uint64 {
	j := (2*r - 1) * 16
	return uint64(b[j]) | uint64(b[j+1])<<32
}

func smix(b []byte, r, N int, v, xy []uint32) {
	var tmp [16]uint32
	R := 32 * r
	x := xy
	y := xy[R:]

	j := 0
	for i := 0; i < R; i++ {
		x[i] = binary.LittleEndian.Uint32(b[j:])
		j += 4
	}
	for i := 0; i < N; i += 2 {
		blockCopy(v[i*R:], x, R)
		blockMix(&tmp, x, y, r)

		blockCopy(v[(i+1)*R:], y, R)
		blockMix(&tmp, y, x, r)
	}
	for i := 0; i < N; i += 2 {
		j := int(integer(x, r) & uint64(N-1))
		blockXOR(x, v[j*R:], R)
		blockMix(&tmp, x, y, r)

		j = int(integer(y, r) & uint64(N-1))
		blockXOR(y, v[j*R:], R)
		blockMix(&tmp, y, x, r)
	}
	j = 0
	for _, v := range x[:R] {
		binary.LittleEndian.PutUint32(b[j:], v)
		j += 4
	}
}

func Key(password, salt []byte, N, r, p, keyLen int) ([]byte, error) {
	if N <= 1 || N&(N-1) != 0 {
		return nil, errors.New("scrypt: N must be > 1 and a power of 2")
	}
	if uint64(r)*uint64(p) >= 1<<30 || r > maxInt/128/p || r > maxInt/256 || N > maxInt/128/r {
		return nil, errors.New("scrypt: parameters are too large")
	}

	var myHash func() hash.Hash
	if *md == "sha256" {
		myHash = sha256.New
	} else if *md == "sha512" {
		myHash = sha512.New
	} else if *md == "sha512_256" {
		myHash = sha512.New512_256
	} else if *md == "md5" {
		myHash = md5.New
	} else if *md == "sha1" {
		myHash = sha1.New
	} else if *md == "rmd128" {
		myHash = ripemd.New128
	} else if *md == "rmd160" {
		myHash = ripemd.New160
	} else if *md == "rmd256" {
		myHash = ripemd.New256
	} else if *md == "sha3_256" {
		myHash = sha3.New256
	} else if *md == "sha3_512" {
		myHash = sha3.New512
	} else if *md == "keccak256" {
		myHash = sha3.NewLegacyKeccak256
	} else if *md == "keccak512" {
		myHash = sha3.NewLegacyKeccak512
	} else if *md == "whirlpool" {
		myHash = whirlpool.New
	} else if *md == "blake256" {
		myHash = blake256.New
	} else if *md == "blake2b256" {
		myHash = crypto.BLAKE2b_256.New
	} else if *md == "blake2b512" {
		myHash = crypto.BLAKE2b_512.New
	} else if *md == "blake2s256" {
		myHash = crypto.BLAKE2s_256.New
	} else if *md == "skein256" {
		g := func() hash.Hash {
			return skein256.New256(nil)
		}
		myHash = g
	} else if *md == "skein512_256" {
		g := func() hash.Hash {
			return skein.New256(nil)
		}
		myHash = g
	} else if *md == "skein512" {
		g := func() hash.Hash {
			return skein.New512(nil)
		}
		myHash = g
	} else if *md == "groestl" {
		myHash = groestl.New256
	} else if *md == "groestl512" {
		myHash = groestl512.New512
	} else if *md == "jh" {
		myHash = jh.New256
	} else if *md == "tiger" {
		myHash = tiger.New
	} else if *md == "tiger128" {
		myHash = tiger128.New
	} else if *md == "tiger160" {
		myHash = tiger160.New
	} else if *md == "tiger2" {
		myHash = tiger.New2
	} else if *md == "tiger2_128" {
		myHash = tiger128.New2
	} else if *md == "tiger2_160" {
		myHash = tiger160.New2
	} else if *md == "sm3" {
		myHash = sm3.New
	} else if *md == "gost94" {
		g := func() hash.Hash {
			return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
		}
		myHash = g
	} else if *md == "streebog256" {
		myHash = gost34112012256.New
	} else if *md == "streebog512" {
		myHash = gost34112012512.New
	} else if *md == "stribog256" {
		myHash = gostribog.New256
	} else if *md == "stribog512" {
		myHash = gostribog.New512
	} else if *md == "lsh256" {
		myHash = lsh256.New
	} else if *md == "lsh512" {
		myHash = lsh512.New
	} else if *md == "lsh512_256" {
		myHash = lsh512.New256
	} else if *md == "blake3" {
		g := func() hash.Hash {
			return blake3.New()
		}
		myHash = g
	}

	xy := make([]uint32, 64*r)
	v := make([]uint32, 32*N*r)
	b := pbkdf2.Key(password, salt, 1, p*128*r, myHash)

	for i := 0; i < p; i++ {
		smix(b[i*128*r:], r, N, v, xy)
	}

	return pbkdf2.Key(password, b, 1, keyLen, myHash), nil
}

func atbash(s string) string {
	res := ""
	for _, c := range s {
		var decodedChar rune
		if c < rune('a') && c < rune('A') || c > rune('z') && c > rune('Z') {
			decodedChar = c
		} else {
			if IsUpper(string(c)) {
				diff := c - 'A'
				decodedChar = 'Z' - diff
			} else {
				diff := c - 'a'
				decodedChar = 'z' - diff
			}
		}
		res = fmt.Sprintf("%s%c", res, decodedChar)
	}
	return res
}

func IsUpper(s string) bool {
	for _, r := range s {
		if !unicode.IsUpper(r) && unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func rot13(input string) string {
	result := make([]string, 0, len(input))
	for _, chr := range input {
		if 'a' <= chr && chr <= 'z' {
			chr = ((chr - 'a' + 13) % 26) + 'a'
		}
		if 'A' <= chr && chr <= 'Z' {
			chr = ((chr - 'A' + 13) % 26) + 'A'
		}
		result = append(result, string(chr))
	}
	output := strings.Join(result, "")
	return output
}

func SplitSubN(s string, n int) []string {
	sub := ""
	subs := []string{}

	runes := bytes.Runes([]byte(s))
	l := len(runes)
	for i, r := range runes {
		sub = sub + string(r)
		if (i+1)%n == 0 {
			subs = append(subs, sub)
			sub = ""
		} else if (i + 1) == l {
			subs = append(subs, sub)
		}
	}

	return subs
}

var letters = []rune(":,()#$%&*~}{[]@!1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[mathrand.Intn(len(letters))]
	}
	return string(b)
}

func validateECPublicKey(curve elliptic.Curve, x, y *big.Int) bool {
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	if x.Cmp(curve.Params().P) >= 0 {
		return false
	}
	if y.Cmp(curve.Params().P) >= 0 {
		return false
	}
	if !curve.IsOnCurve(x, y) {
		return false
	}
	return true
}

type Mode int

const (
	Encrypt Mode = iota
	Decrypt
)

const (
	lAlphabet = "HXUCZVAMDSLKPEFJRIGTWOBNYQ"
	rAlphabet = "PTLNBQDEOYSFAVZKGJRIHWXUMC"
)

func Chao(text string, mode Mode, showSteps bool) string {
	len := len(text)
	if utf8.RuneCountInString(text) != len {
		fmt.Println("Text contains non-ASCII characters")
		return ""
	}
	left := lAlphabet
	right := rAlphabet
	eText := make([]byte, len)
	temp := make([]byte, 26)

	for i := 0; i < len; i++ {
		if showSteps {
			fmt.Fprintln(os.Stderr, left, " ", right)
		}
		var index int
		if mode == Encrypt {
			index = strings.IndexByte(right, text[i])
			eText[i] = left[index]
		} else {
			index = strings.IndexByte(left, text[i])
			eText[i] = right[index]
		}
		if i == len-1 {
			break
		}

		for j := index; j < 26; j++ {
			temp[j-index] = left[j]
		}
		for j := 0; j < index; j++ {
			temp[26-index+j] = left[j]
		}
		store := temp[1]
		for j := 2; j < 14; j++ {
			temp[j-1] = temp[j]
		}
		temp[13] = store
		left = string(temp[:])

		for j := index; j < 26; j++ {
			temp[j-index] = right[j]
		}
		for j := 0; j < index; j++ {
			temp[26-index+j] = right[j]
		}
		store = temp[0]
		for j := 1; j < 26; j++ {
			temp[j-1] = temp[j]
		}
		temp[25] = store
		store = temp[2]
		for j := 3; j < 14; j++ {
			temp[j-1] = temp[j]
		}
		temp[13] = store
		right = string(temp[:])
	}
	return string(eText[:])
}
