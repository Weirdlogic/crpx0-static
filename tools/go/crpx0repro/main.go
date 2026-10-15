// crpx0repro: independent re-implementation of the CRPx0 static unpack, for
// cross-checking the Python tools (crpx0_stage1.py, crpx0_stage2.py,
// crpx0_config.py). Go standard library only: debug/pe for layout,
// encoding/base64 + compress/zlib for stage 3, crypto/aes + crypto/hmac for
// Fernet, and a regex (not a Python parser) to find dx() literals.
// It reads files and writes files. It never executes sample content.
//
// Usage: crpx0repro <stage1.exe> <outdir>
// Writes outdir/stage2.bin, outdir/stage3.py.txt, outdir/repro.json
package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"debug/pe"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// readVA returns n bytes at virtual address va using the section table.
func readVA(f *pe.File, va uint32, n int) []byte {
	base := f.OptionalHeader.(*pe.OptionalHeader32).ImageBase
	rva := va - base
	for _, s := range f.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
			d, err := s.Data()
			must(err)
			o := rva - s.VirtualAddress
			if int(o)+n > len(d) {
				n = len(d) - int(o)
			}
			return d[o : int(o)+n]
		}
	}
	panic(fmt.Sprintf("va %#x not mapped", va))
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Layer 1: stage 1 decoder at 0x401566.
func layer1(path string) []byte {
	f, err := pe.Open(path)
	must(err)
	defer f.Close()
	x1 := readVA(f, 0x7b38c0, 1)[0]
	x2 := readVA(f, 0x7b38c1, 1)[0]
	k1 := append([]byte{}, readVA(f, 0x7b3840, 64)...)
	k2 := append([]byte{}, readVA(f, 0x7b3880, 64)...)
	for i := range k1 {
		k1[i] ^= x1
		k2[i] ^= x2
	}
	n := int(binary.LittleEndian.Uint32(readVA(f, 0x7b3820, 4)))
	src := readVA(f, 0x403020, n)
	out := make([]byte, n)
	for i, b := range src {
		b ^= k2[i&63]
		b = b>>1 | b<<7
		b = ^b
		out[i] = b ^ k1[i&63]
	}
	return out
}

// Layer 2: stage 2 bootstrap (XOR 0xD6) -> base64 -> zlib -> stage 3 source.
func layer2(stage2 string) ([]byte, string) {
	f, err := pe.Open(stage2)
	must(err)
	defer f.Close()
	const start, end = 0x40b260, 0x7abde0
	enc := readVA(f, start, end-start)
	boot := make([]byte, len(enc))
	for i, b := range enc {
		boot[i] = b ^ 0xd6
	}
	m := regexp.MustCompile(`= '([A-Za-z0-9+/=]{1000,})'`).FindSubmatch(boot)
	if m == nil {
		panic("bootstrap blob not found")
	}
	raw, err := base64.StdEncoding.DecodeString(string(m[1]))
	must(err)
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	must(err)
	src, err := io.ReadAll(zr)
	must(err)
	return src, sum(m[1])
}

// Fernet decrypt (spec: version 0x80 | ts(8) | iv(16) | ct | hmac(32)).
func fernet(keyB64, tokB64 string) ([]byte, uint64) {
	key, err := base64.URLEncoding.DecodeString(keyB64)
	must(err)
	tok, err := base64.URLEncoding.DecodeString(tokB64)
	must(err)
	if len(key) != 32 || tok[0] != 0x80 {
		panic("bad fernet input")
	}
	sign, encKey := key[:16], key[16:]
	body, tag := tok[:len(tok)-32], tok[len(tok)-32:]
	mac := hmac.New(sha256.New, sign)
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), tag) {
		panic("fernet HMAC mismatch")
	}
	ts := binary.BigEndian.Uint64(tok[1:9])
	iv, ct := tok[9:25], tok[25:len(tok)-32]
	blk, err := aes.NewCipher(encKey)
	must(err)
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(pt, ct)
	p := int(pt[len(pt)-1])
	return pt[:len(pt)-p], ts
}

func ints(s string) []byte {
	var out []byte
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		v, err := strconv.Atoi(t)
		must(err)
		out = append(out, byte(v))
	}
	return out
}

type dxString struct {
	Line   int    `json:"line"`
	Len    int    `json:"len"`
	SHA256 string `json:"sha256"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: crpx0repro <stage1.exe> <outdir>")
		os.Exit(2)
	}
	out := os.Args[2]
	s2 := layer1(os.Args[1])
	s2p := filepath.Join(out, "stage2.bin")
	must(os.WriteFile(s2p, s2, 0o400))
	s3, blobSum := layer2(s2p)
	must(os.WriteFile(filepath.Join(out, "stage3.py.txt"), s3, 0o400))
	src := string(s3)

	lit := func(name string) string {
		m := regexp.MustCompile(`(?m)^` + name + ` = b"([^"]*)"`).FindStringSubmatch(src)
		if m == nil {
			panic(name)
		}
		return m[1]
	}
	xk, ts := fernet(lit("AES_KEY_B64"), lit("ENCRYPTED_XOR_KEY"))

	// line numbers of each dx( call; resolve dx(name) to `name = [..]` earlier in the file
	lines := strings.Split(src, "\n")
	inline := regexp.MustCompile(`dx\(\[([0-9,\s]+)\]`)
	named := regexp.MustCompile(`dx\(([A-Za-z_][A-Za-z0-9_]*)\)`)
	var dx []dxString
	add := func(line int, vals []byte) {
		p := make([]byte, len(vals))
		for i, b := range vals {
			p[i] = b ^ xk[i%len(xk)]
		}
		dx = append(dx, dxString{line, len(vals), sum(p)})
	}
	var remote string
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "def dx(") {
			continue
		}
		for _, m := range inline.FindAllStringSubmatch(l, -1) {
			v := ints(m[1])
			add(i+1, v)
			if strings.Contains(l, "REMOTE_URLS =") {
				p := make([]byte, len(v))
				for j, b := range v {
					p[j] = b ^ xk[j%len(xk)]
				}
				remote = string(p)
			}
		}
		for _, m := range named.FindAllStringSubmatch(l, -1) {
			def := regexp.MustCompile(`^\s*` + m[1] + ` = \[([0-9,\s]+)\]`)
			for j := i; j >= 0 && j > i-40; j-- {
				if d := def.FindStringSubmatch(lines[j]); d != nil {
					add(i+1, ints(d[1]))
					break
				}
			}
		}
	}
	sort.Slice(dx, func(a, b int) bool {
		if dx[a].Line != dx[b].Line {
			return dx[a].Line < dx[b].Line
		}
		return dx[a].SHA256 < dx[b].SHA256
	})
	var urls []string
	for _, u := range strings.Split(remote, "|") {
		if u = strings.TrimSpace(u); u != "" {
			urls = append(urls, sum([]byte(u)))
		}
	}
	res := map[string]any{
		"stage2_sha256":       sum(s2),
		"stage2_size":         len(s2),
		"stage2_is_pe":        bytes.HasPrefix(s2, []byte("MZ")),
		"stage3_blob_sha256":  blobSum,
		"stage3_sha256":       sum(s3),
		"xor_key_sha256":      sum(xk),
		"fernet_timestamp":    ts,
		"dx_strings":          dx,
		"remote_url_sha256s":  urls,
		"remote_url_count":    len(urls),
	}
	j, _ := json.MarshalIndent(res, "", " ")
	must(os.WriteFile(filepath.Join(out, "repro.json"), j, 0o644))
	fmt.Printf("stage2 %s\nstage3 %s\nxor key sha256 %s ts %d\ndx strings %d, remote urls %d\n",
		sum(s2), sum(s3), sum(xk), ts, len(dx), len(urls))
}
