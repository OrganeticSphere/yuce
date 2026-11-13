// Command signed_note_vectors writes the vectors that check the signed checkpoints of YuCe against the reference implementation of
// their format: golang.org/x/mod/sumdb/note, the code of the authors of C2SP signed-note, and golang.org/x/mod/sumdb/tlog for the
// RFC 6962 tree a checkpoint names. The kernel's tests read the file (crates/sbgk-core/src/audit/signed_note_vectors.json); Go is
// needed only to write it again.
//
// Deterministic: the keys come from a fixed seed and Ed25519 signatures are deterministic, so the same Go and module versions
// write the same bytes.
//
//	go run . > ../../crates/sbgk-core/src/audit/signed_note_vectors.json
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// seed is the deterministic source of the keys: SHA-256 blocks of a counter.
type seed struct {
	n   uint64
	buf []byte
}

func (s *seed) Read(p []byte) (int, error) {
	for i := range p {
		if len(s.buf) == 0 {
			h := sha256.Sum256([]byte(fmt.Sprintf("yuce/signed-note-vectors/%d", s.n)))
			s.n++
			s.buf = h[:]
		}
		p[i] = s.buf[0]
		s.buf = s.buf[1:]
	}
	return len(p), nil
}

type key struct {
	Name string `json:"name"`
	Skey string `json:"skey"`
	Vkey string `json:"vkey"`
}

type keyCase struct {
	Case string `json:"case"`
	Key  string `json:"key"`
	Go   string `json:"go"`
}

type signedCase struct {
	Case    string   `json:"case"`
	Text    string   `json:"text"`
	Signers []string `json:"signers"`
	Note    string   `json:"note"`
}

type openCase struct {
	Case     string   `json:"case"`
	Msg      string   `json:"msg_b64"`
	Known    []string `json:"known"`
	Verified []string `json:"verified"`
	Go       string   `json:"go"`
}

type treeCase struct {
	Size int    `json:"size"`
	Root string `json:"root"`
}

type vectors struct {
	Note         string       `json:"_note"`
	Generator    string       `json:"generator"`
	Keys         []key        `json:"keys"`
	VerifierKeys []keyCase    `json:"verifier_keys"`
	SignerKeys   []keyCase    `json:"signer_keys"`
	Signed       []signedCase `json:"signed"`
	Open         []openCase   `json:"open"`
	Trees        []treeCase   `json:"trees"`
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// verdict names the outcome of the reference code: "ok" or the kind of its error.
func verdict(err error) string {
	var unverified *note.UnverifiedNoteError
	var invalid *note.InvalidSignatureError
	switch {
	case err == nil:
		return "ok"
	case errors.As(err, &unverified):
		return "unverified"
	case errors.As(err, &invalid):
		return "invalid signature"
	default:
		return err.Error()
	}
}

func splitKey(vkey string) (name, hash, data string) {
	parts := strings.SplitN(vkey, "+", 3)
	return parts[0], parts[1], parts[2]
}

func keyID(name string, data []byte) uint32 {
	h := sha256.Sum256(append(append([]byte(name), '\n'), data...))
	return binary.BigEndian.Uint32(h[:4])
}

// withID writes a verifier key of `name` and key bytes `data` (algorithm byte first) with its correct id.
func withID(name string, data []byte) string {
	return fmt.Sprintf("%s+%08x+%s", name, keyID(name, data), base64.StdEncoding.EncodeToString(data))
}

// sigLine is a signature line of `name` over raw bytes `id || sig`.
func sigLine(name string, id uint32, sig []byte) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], id)
	return "— " + name + " " + base64.StdEncoding.EncodeToString(append(b[:], sig...)) + "\n"
}

func main() {
	modVersion := "unknown"
	for _, line := range strings.Split(string(must(os.ReadFile("go.mod"))), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "golang.org/x/mod" {
			modVersion = f[1]
		} else if len(f) >= 3 && f[0] == "require" && f[1] == "golang.org/x/mod" {
			modVersion = f[2]
		}
	}
	v := vectors{
		Note: "Made by the reference implementation of C2SP signed-note (golang.org/x/mod/sumdb/note) and its RFC 6962 tree " +
			"(golang.org/x/mod/sumdb/tlog). 'go' is that code's outcome; the kernel's tests hold their own to it, and name " +
			"each case where the kernel is stricter on purpose.",
		Generator: fmt.Sprintf("scripts/signed_note_vectors, %s, golang.org/x/mod %s", runtime.Version(), modVersion),
	}

	// keys of several names, from the fixed seed
	rand := &seed{}
	byName := map[string]key{}
	for _, name := range []string{"operator", "witness", "PeterNeumann", "example.com/log", "yuce/run-1", "café", "日本"} {
		skey, vkey := must2(note.GenerateKey(rand, name))
		k := key{Name: name, Skey: skey, Vkey: vkey}
		v.Keys = append(v.Keys, k)
		byName[name] = k
	}
	op := byName["operator"]
	wit := byName["witness"]
	name, hash, data := splitKey(op.Vkey)
	raw := must(base64.StdEncoding.DecodeString(data))

	// verifier keys
	identity := append([]byte{1, 1}, make([]byte, 31)...)
	vk := func(c, k string) {
		_, err := note.NewVerifier(k)
		v.VerifierKeys = append(v.VerifierKeys, keyCase{c, k, verdict(err)})
	}
	for _, k := range v.Keys {
		vk("generated "+k.Name, k.Vkey)
	}
	vk("id in upper case", name+"+"+strings.ToUpper(hash)+"+"+data)
	vk("id of another key", name+"+"+fmt.Sprintf("%08x", keyID(name, raw)^1)+"+"+data)
	vk("id of seven digits", name+"+"+hash[:7]+"+"+data)
	vk("id of nine digits", name+"+0"+hash+"+"+data)
	vk("base64 with a bad character", name+"+"+hash+"+"+data[:10]+"*"+data[11:])
	vk("algorithm byte 2", withID(name, append([]byte{2}, raw[1:]...)))
	vk("key of 31 bytes", withID(name, raw[:32]))
	vk("key of 33 bytes", withID(name, append(append([]byte{}, raw...), 0)))
	vk("empty name", withID("", raw))
	vk("name with a space", withID("op erator", raw))
	vk("name with a no-break space", withID("op erator", raw))
	vk("name with a control character", withID("op\u0001erator", raw))
	vk("weak key, the identity point", withID("weak", identity))
	vk("line end after the key", op.Vkey+"\n")
	vk("space before the key", " "+op.Vkey)

	// signer keys
	sk := func(c, k string) {
		_, err := note.NewSigner(k)
		v.SignerKeys = append(v.SignerKeys, keyCase{c, k, verdict(err)})
	}
	for _, k := range v.Keys {
		sk("generated "+k.Name, k.Skey)
	}
	sparts := strings.SplitN(op.Skey, "+", 5)
	sk("id in upper case", strings.Join([]string{sparts[0], sparts[1], sparts[2], strings.ToUpper(sparts[3]), sparts[4]}, "+"))
	sk("id of another key", strings.Join([]string{sparts[0], sparts[1], sparts[2], fmt.Sprintf("%08x", keyID(name, raw)^1), sparts[4]}, "+"))
	sk("PRIVATE+KEYS", strings.Replace(op.Skey, "PRIVATE+KEY+", "PRIVATE+KEYS+", 1))
	sk("verifier key given as signer key", op.Vkey)

	// signed notes
	signers := map[string]note.Signer{}
	for _, k := range v.Keys {
		signers[k.Name] = must(note.NewSigner(k.Skey))
	}
	long := strings.Repeat("A line of a long note, to sign more than a block of bytes.\n", 60)
	texts := []struct{ c, t string }{
		{"one line", "a\n"},
		{"the example of the documentation", "If you think cryptography is the answer to your problem,\nthen you don't know what your problem is.\n"},
		{"a checkpoint", "yuce/run-1\n42\nn+8wvmZRY5/X3oR6vMbvwGHqmLrIX5KVDd8F0P5xnHU=\n"},
		{"text outside ASCII", "café 日本\n"},
		{"a blank line inside", "a\n\nb\n"},
		{"a line end only", "\n"},
		{"a long text", long},
	}
	for _, t := range texts {
		for _, ss := range [][]string{{"operator"}, {"café"}, {"operator", "witness"}} {
			list := []note.Signer{}
			for _, s := range ss {
				list = append(list, signers[s])
			}
			msg := must(note.Sign(&note.Note{Text: t.t}, list...))
			v.Signed = append(v.Signed, signedCase{t.c + ", signed by " + strings.Join(ss, " and "), t.t, ss, string(msg)})
		}
	}

	// opening notes
	opV := must(note.NewVerifier(op.Vkey))
	witV := must(note.NewVerifier(wit.Vkey))
	weakV := withID("weak", identity)
	text := "yuce/run-1\n42\nn+8wvmZRY5/X3oR6vMbvwGHqmLrIX5KVDd8F0P5xnHU=\n"
	good := must(note.Sign(&note.Note{Text: text}, signers["operator"]))
	both := must(note.Sign(&note.Note{Text: text}, signers["operator"], signers["witness"]))
	byOther := must(note.Sign(&note.Note{Text: text}, signers["PeterNeumann"]))
	goodLine := string(good[len(text)+1:])
	sigRaw := must(base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.SplitN(goodLine, " ", 3)[2], "\n")))
	opID := binary.BigEndian.Uint32(sigRaw[:4])
	bad := append([]byte{}, sigRaw[4:]...)
	bad[10] ^= 1
	badLine := sigLine("operator", opID, bad)
	witLine := string(both[len(text)+1+len(goodLine):])
	witRaw := must(base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.SplitN(witLine, " ", 3)[2], "\n")))
	witBad := append([]byte{}, witRaw[4:]...)
	witBad[3] ^= 1
	witBadLine := sigLine("witness", binary.BigEndian.Uint32(witRaw[:4]), witBad)
	forged := make([]byte, 64)
	forged[0] = 1
	weakName, weakHash, _ := splitKey(weakV)
	var weakID uint32
	fmt.Sscanf(weakHash, "%08x", &weakID)
	many := goodLine
	for i := 0; i < 100; i++ {
		many += sigLine(fmt.Sprintf("unknown%d", i), uint32(i), make([]byte, 64))
	}
	known := []string{op.Vkey, wit.Vkey}
	open := func(c string, msg []byte, knownKeys []string) {
		list := []note.Verifier{}
		for _, k := range knownKeys {
			list = append(list, must(note.NewVerifier(k)))
		}
		n, err := note.Open(msg, note.VerifierList(list...))
		verified := []string{}
		if err == nil {
			for _, s := range n.Sigs {
				verified = append(verified, s.Name)
			}
		}
		v.Open = append(v.Open, openCase{c, base64.StdEncoding.EncodeToString(msg), knownKeys, verified, verdict(err)})
	}
	_ = opV
	_ = witV
	open("signed by the operator", good, known)
	open("signed by the operator and the witness", both, known)
	open("signed by an unknown key only", byOther, known)
	open("a byte of the text changed", bytes.Replace(good, []byte("42"), []byte("43"), 1), known)
	open("a byte of the signature changed", []byte(text+"\n"+badLine), known)
	open("no line end at the end", good[:len(good)-1], known)
	open("no blank line before the signatures", []byte(text+goodLine), known)
	open("a carriage return in the text", []byte(strings.Replace(text, "42\n", "42\r\n", 1)+"\n"+goodLine), known)
	open("a tab in the text", []byte(strings.Replace(text, "42", "4\t2", 1)+"\n"+goodLine), known)
	open("a byte that is not UTF-8 in the text", append([]byte(text[:3]), append([]byte{0xff}, []byte(text[3:]+"\n"+goodLine)...)...), known)
	open("a signature line without the em dash", []byte(text+"\n"+strings.Replace(goodLine, "— ", "- ", 1)), known)
	open("a signature line whose name holds a plus", []byte(text+"\n"+sigLine("oper+ator", opID, sigRaw[4:])), known)
	open("a signature line with no base64", []byte(text+"\n— operator \n"), known)
	open("a signature of four bytes", []byte(text+"\n— operator "+base64.StdEncoding.EncodeToString(sigRaw[:4])+"\n"), known)
	open("a signature line without a space", []byte(text+"\n— operator\n"), known)
	open("a space after the base64", []byte(text+"\n"+strings.TrimSuffix(goodLine, "\n")+" \n"), known)
	open("the same signature twice", []byte(text+"\n"+goodLine+goodLine), known)
	open("a bad signature of a key, then its good one", []byte(text+"\n"+badLine+goodLine), known)
	open("a good signature of a key, then a bad one", []byte(text+"\n"+goodLine+badLine), known)
	open("a good signature and a bad one of another known key", []byte(text+"\n"+goodLine+witBadLine), known)
	open("a good signature and a bad one of a key not known", []byte(text+"\n"+goodLine+witBadLine), []string{op.Vkey})
	open("a good signature and a line of an unknown key", []byte(text+"\n"+goodLine+sigLine("someone", 7, make([]byte, 64))), known)
	open("the signature under another known name", []byte(text+"\n"+sigLine("witness", opID, sigRaw[4:])), known)
	open("101 signature lines", []byte(text+"\n"+many), known)
	open("a blank line between the signatures", []byte(text+"\n"+goodLine+"\n"+witLine), known)
	open("no known key", good, []string{})
	open("a forged signature for a weak key", []byte(text+"\n"+sigLine(weakName, weakID, forged)), []string{weakV})
	open("a good signature and a line whose name holds a plus", []byte(text+"\n"+goodLine+sigLine("some+one", 7, make([]byte, 64))), known)
	open("a good signature and a signature of four bytes", []byte(text+"\n"+goodLine+"— someone "+base64.StdEncoding.EncodeToString(sigRaw[:4])+"\n"), known)
	hundred := goodLine
	for i := 0; i < 99; i++ {
		hundred += sigLine(fmt.Sprintf("unknown%d", i), uint32(i), make([]byte, 64))
	}
	open("100 signature lines", []byte(text+"\n"+hundred), known)
	b64 := strings.TrimSuffix(strings.SplitN(goodLine, " ", 3)[2], "\n")
	open("a signature without its base64 padding", []byte(text+"\n— operator "+strings.TrimRight(b64, "=")+"\n"), known)
	// the last character before the padding carries two bits the decoded bytes do not use: set one of them
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	at := len(b64) - 2
	loose := b64[:at] + string(alphabet[strings.IndexByte(alphabet, b64[at])|1]) + b64[at+1:]
	if loose != b64 && bytes.Equal(must(base64.StdEncoding.DecodeString(loose)), sigRaw) {
		open("a signature whose base64 sets the unused padding bits", []byte(text+"\n— operator "+loose+"\n"), known)
	}
	upper := strings.SplitN(op.Vkey, "+", 3)
	open("a verifier key with its id in upper case", good, []string{upper[0] + "+" + strings.ToUpper(upper[1]) + "+" + upper[2]})

	// RFC 6962 trees over frame hashes
	var stored []tlog.Hash
	reader := tlog.HashReaderFunc(func(idx []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(idx))
		for i, x := range idx {
			out[i] = stored[x]
		}
		return out, nil
	})
	sizes := map[int]bool{}
	for _, n := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 31, 32, 33, 64, 100, 255, 256, 257, 1000} {
		sizes[n] = true
	}
	for i := 0; i < 1000; i++ {
		frame := sha256.Sum256([]byte(fmt.Sprintf("frame %d", i)))
		stored = append(stored, must(tlog.StoredHashes(int64(i), frame[:], reader))...)
		if sizes[i+1] {
			root := must(tlog.TreeHash(int64(i+1), reader))
			v.Trees = append(v.Trees, treeCase{i + 1, fmt.Sprintf("%x", root[:])})
		}
	}

	out := must(json.MarshalIndent(v, "", "  "))
	os.Stdout.Write(append(out, '\n'))
}

func must2(a, b string, err error) (string, string) {
	if err != nil {
		panic(err)
	}
	return a, b
}
