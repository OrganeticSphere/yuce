# JSON RFC corpus: RFC 4627 and RFC 7159

Two editions of the JSON specification, as published by the RFC Editor: a corpus for withdrawals on a standard whose text changed
between editions. RFC 8259, the current edition, is not in the corpus; it is named only as the reason of one withdrawal.

| File | Document | Published | Source |
|---|---|---|---|
| `rfc4627.md` | RFC 4627, The application/json Media Type for JavaScript Object Notation (JSON) | July 2006 | https://www.rfc-editor.org/rfc/rfc4627.txt |
| `rfc7159.md` | RFC 7159, The JavaScript Object Notation (JSON) Data Interchange Format | March 2014 | https://www.rfc-editor.org/rfc/rfc7159.txt |

- Every file holds the bytes of the RFC Editor's plain-text edition unchanged, form feeds included: 16,319 and 27,451 bytes,
  SHA-256 `a31e8400…6518d` and `50aa7253…22342` (in full in `../gold/json-rfc-4627-7159-reference.json`).
- Only the file names differ: `.md` instead of `.txt`. The kernel takes documents from a corpus manifest as Markdown candidates only,
  and neither RFC has a line that starts with `#` or a code fence, so the kernel cuts it into reading sections exactly as it would
  cut the `.txt` file (`benchmarks/test_json_rfc_corpus.py` checks both).
- `reports.txt` gives the files in publication order.
- The texts are copyright of the IETF Trust (RFC 7159) and of the Internet Society (RFC 4627) and of the persons named as their
  authors, under BCP 78 and the IETF Trust's Legal Provisions. They are reproduced here in full and without modification, with
  their copyright notices inside, to pin the bytes of a benchmark; they are not modified or used to make derivative works.

**`../gold/json-rfc-4627-7159-reference.json` is the reference, fixed before any run.**
- It is based on the official change lists: RFC 7159 Appendix A (changes from RFC 4627) and RFC 8259 Appendix A (changes from
  RFC 7159).
- Four sentences that a later edition changed, each withdrawn in one step of the run's plan (`withdrawal.json`):
  - W1, RFC 4627: "A JSON text is a serialized object or array." (7159: a JSON text is any serialized value);
  - W2, RFC 4627: "A JSON text can be safely passed into JavaScript's eval() function" (removed by erratum 3607);
  - W3, RFC 4627: "JSON text SHALL be encoded in Unicode." (rewritten in 7159);
  - W4, RFC 7159: "JSON text SHALL be encoded in UTF-8, UTF-16, or UTF-32." (8259: UTF-8 over a network).
- One control that no edition changed: C1, "The names within an object SHOULD be unique."
- Each sentence is given with its file, byte offset and number of occurrences (one each).
- The withdrawals are a synthetic benchmark intervention: the IETF withdrew none of these sentences, later editions changed them.

`benchmarks/test_json_rfc_corpus.py` checks:
- the bytes of both files against the reference;
- every sentence of the reference at its byte offset, once, inside one reading section of the kernel;
- the withdrawal plan against the reference.
