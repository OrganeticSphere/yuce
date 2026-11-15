# The journal as W3C PROV-O

`sample.prov.jsonld` is what `sbgk audit-prov` writes for a small journal:
1. an agent quotes two lines of a document and writes a claim on both;
2. the owner withdraws the first quote;
3. the document gets a new version, and then its first bytes back.

To make one from your own journal:

```bash
sbgk audit-prov --wal run.wal --out run.prov.jsonld
```

The file is JSON-LD with its context inside, so any RDF tool reads it without fetching anything. The same journal always gives the
same bytes.

## What is in it

| In the journal | In the file |
|---|---|
| A version of a document | `prov:Entity` (`yuce:DocumentVersion`), `prov:specializationOf` its document; a later version `prov:wasRevisionOf` the one before |
| A record of an agent | `prov:Entity` (`yuce:Record`), `prov:wasAttributedTo` its author, `prov:wasGeneratedBy` its frame, `prov:wasDerivedFrom` what it rests on |
| An observation's quote | `prov:wasQuotedFrom` the version, with the bytes `yuce:start`..`yuce:end` and the text as `prov:value` |
| A period in which a record stood | `prov:Entity` (`yuce:Standing`), `prov:specializationOf` the record; when it ended, `prov:wasInvalidatedBy` that frame, with a `prov:Invalidation` whose `yuce:reason` is `withdrawn`, `new_version`, `basis` (with `yuce:fallenBy`) or `answer` |
| A frame | `prov:Activity` with `yuce:frame`, `yuce:frameHash` and `yuce:command`, `prov:wasAssociatedWith` the subject that wrote it |
| A seal | `prov:Entity` (`yuce:Seal`) with its roots |

A record itself is never invalidated: the journal keeps it, and only its standing ends. There are no times: the journal holds none,
and frames are ordered by their number.

## What fell when the first quote was withdrawn

```sparql
PREFIX prov: <http://www.w3.org/ns/prov#>
PREFIX yuce: <https://organetic.ai/ns/yuce#>
SELECT ?record ?kind ?reason WHERE {
  ?frame yuce:command "revoke" .
  ?standing prov:wasInvalidatedBy ?frame ; prov:specializationOf ?record ; prov:qualifiedInvalidation ?why .
  ?why yuce:reason ?reason .
  ?record yuce:kind ?kind .
}
```

The observation is the one `withdrawn`. The claim fell with it: `basis`, and its `yuce:fallenBy` names the observation.

## The content hash

The node of type `yuce:Export` names `yuce:contentHash`: the SHA-256 of the file's canonical JSON (RFC 8785) without that one
property. If the hash does not match, the file was changed after it was written. The export also names the last frame's hash
(`yuce:walHead`) and the last seal, so `sbgk audit-verify` can tie the file to its journal.
