// crpx0fixtures: independent writer of CRPx0-format test files, for checking
// that tools/crpx0_decrypt.py reads the format the malware writes.
//
// Written from stage 3 stage2_encrypt() (L1335-1350 of stage3_752b8fe4...),
// in a different language and with different libraries from the decryptor:
//   key   = base64url(32 random bytes)                    (Fernet.generate_key)
//   token = base64url(0x80 | ts | iv | AES-128-CBC(PKCS7(head)) | HMAC-SHA256)
//           with signing key = key[:16], encryption key = key[16:]  (Fernet spec)
//   blob  = RSA-OAEP(SHA-256, MGF1-SHA-256, no label)(key)
//   file  = u32le len(blob) | blob | u64le len(token) | token | rest of plaintext
//   head  = first 1 MiB (f.read(1024*1024)), rest = remainder (f.read())
// Key material is generated here; no operator key is involved. Nothing is read
// from or written over any real file: plaintexts are random bytes.
//
// Usage: crpx0fixtures <outdir>
// Writes outdir/enc/*.crpx0, outdir/fernet.key, outdir/rsa_private.pem,
// outdir/manifest.json (sha256 and size of every plaintext).
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const head = 1024 * 1024

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func fernetToken(key, msg []byte) []byte {
	sign, enc := key[:16], key[16:]
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	must(err)
	pad := 16 - len(msg)%16
	pt := append(append([]byte{}, msg...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	blk, err := aes.NewCipher(enc)
	must(err)
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, pt)
	body := []byte{0x80}
	body = binary.BigEndian.AppendUint64(body, uint64(time.Now().Unix()))
	body = append(append(body, iv...), ct...)
	m := hmac.New(sha256.New, sign)
	m.Write(body)
	tok := append(body, m.Sum(nil)...)
	return []byte(base64.URLEncoding.EncodeToString(tok))
}

type entry struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: crpx0fixtures <outdir>")
		os.Exit(2)
	}
	out := os.Args[1]
	must(os.MkdirAll(filepath.Join(out, "enc"), 0o755))

	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	must(err)
	key := []byte(base64.URLEncoding.EncodeToString(raw))
	must(os.WriteFile(filepath.Join(out, "fernet.key"), key, 0o600))

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	must(err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	must(err)
	must(os.WriteFile(filepath.Join(out, "rsa_private.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	blob, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, key, nil)
	must(err)

	var manifest []entry
	for _, n := range []int{0, 1, 15, 16, 17, 255, 4096, head - 1, head, head + 1, 2*head + 777} {
		plain := make([]byte, n)
		_, err := rand.Read(plain)
		must(err)
		h := plain
		var rest []byte
		if n > head {
			h, rest = plain[:head], plain[head:]
		}
		tok := fernetToken(raw, h)
		var f bytes.Buffer
		f.Write(binary.LittleEndian.AppendUint32(nil, uint32(len(blob))))
		f.Write(blob)
		f.Write(binary.LittleEndian.AppendUint64(nil, uint64(len(tok))))
		f.Write(tok)
		f.Write(rest)
		name := fmt.Sprintf("go_%d.bin", n)
		must(os.WriteFile(filepath.Join(out, "enc", name+".crpx0"), f.Bytes(), 0o644))
		s := sha256.Sum256(plain)
		manifest = append(manifest, entry{name, n, hex.EncodeToString(s[:])})
	}
	j, _ := json.MarshalIndent(manifest, "", " ")
	must(os.WriteFile(filepath.Join(out, "manifest.json"), j, 0o644))
	fmt.Printf("%d fixtures written to %s\n", len(manifest), out)
}
