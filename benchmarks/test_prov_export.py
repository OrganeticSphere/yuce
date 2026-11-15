"""The PROV-O export read by a tool that is not ours (0.2.2): rdflib parses the sample in examples/prov-export, and its queries
give what the export means. The sample is the export of the fixture journal of crates/sbgk-core/src/audit/prov_tests.rs, which
checks it byte for byte. Without rdflib the test is skipped, unless CI is set: CI installs it.
"""
import hashlib
import json
import os
import pathlib
import unittest

SAMPLE = pathlib.Path(__file__).resolve().parent.parent / "examples" / "prov-export" / "sample.prov.jsonld"
PREFIXES = "PREFIX prov: <http://www.w3.org/ns/prov#> PREFIX yuce: <https://organetic.ai/ns/yuce#> "

try:
    import rdflib
except ImportError:
    rdflib = None


def canonical(value) -> str:
    """RFC 8785 for what the export holds: whole numbers, strings, and keys in ASCII."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class ContentHash(unittest.TestCase):
    def test_the_named_content_hash_is_the_sha256_of_the_document_without_it(self):
        document = json.loads(SAMPLE.read_text(encoding="utf-8"))
        self.assertEqual(SAMPLE.read_text(encoding="utf-8"), canonical(document), "the file is the canonical text")
        export = next(n for n in document["@graph"] if "yuce:Export" in n["@type"])
        named = export.pop("yuce:contentHash")
        self.assertEqual(hashlib.sha256(canonical(document).encode("utf-8")).hexdigest(), named)


@unittest.skipIf(rdflib is None and not os.environ.get("CI"), "no rdflib")
class ReadByRdflib(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = rdflib.Graph()
        cls.graph.parse(data=SAMPLE.read_text(encoding="utf-8"), format="json-ld")

    def rows(self, query):
        return sorted(tuple(str(x) for x in row) for row in self.graph.query(PREFIXES + query))

    def test_the_triples_are_in_the_default_graph_and_the_links_are_iris(self):
        self.assertGreater(len(self.graph), 100)
        prov = rdflib.Namespace("http://www.w3.org/ns/prov#")
        yuce = rdflib.Namespace("https://organetic.ai/ns/yuce#")
        for p in (prov.wasDerivedFrom, prov.wasQuotedFrom, prov.wasGeneratedBy, prov.specializationOf, yuce.fallenBy):
            objects = list(self.graph.objects(None, p))
            self.assertTrue(objects, p)
            self.assertTrue(all(isinstance(o, rdflib.URIRef) for o in objects), p)

    def test_who_quoted_which_version_of_the_document(self):
        quoted = self.rows("""SELECT ?subject ?start ?end WHERE {
            ?r yuce:kind "observe" ; prov:wasQuotedFrom ?v ; prov:wasAttributedTo ?a ; yuce:start ?start ; yuce:end ?end .
            ?v prov:specializationOf ?d . ?d yuce:docId "d" . ?a yuce:subject ?subject . }""")
        self.assertEqual(quoted, [("worker", "0", "30"), ("worker", "31", "67")])

    def test_what_the_withdrawal_made_fall_and_why(self):
        fell = self.rows("""SELECT ?kind ?reason WHERE {
            ?f yuce:command "revoke" . ?s prov:wasInvalidatedBy ?f ; prov:specializationOf ?r ; prov:qualifiedInvalidation ?q .
            ?q prov:activity ?f ; yuce:reason ?reason . ?r yuce:kind ?kind . }""")
        self.assertEqual(fell, [("claim", "basis"), ("observe", "withdrawn")])
        # the claim fell with the observation that was withdrawn
        basis = self.rows("""SELECT ?ground WHERE { ?r yuce:kind "claim" . ?s prov:specializationOf ?r ; prov:qualifiedInvalidation ?q .
            ?q yuce:fallenBy ?g . ?g yuce:kind ?ground . }""")
        self.assertEqual(basis, [("observe",)])

    def test_a_new_version_stops_a_quote_and_the_old_bytes_put_back_make_it_stand_again(self):
        periods = self.rows("""SELECT ?from ?to WHERE {
            ?r prov:value "The second line names its exception." . ?s prov:specializationOf ?r ; prov:wasGeneratedBy ?g . ?g yuce:frame ?from .
            OPTIONAL { ?s prov:wasInvalidatedBy ?i . ?i yuce:frame ?to . } }""")
        self.assertEqual([p[0] for p in periods], ["2", "7"])
        self.assertEqual(periods[0][1], "6")
        self.assertEqual(periods[1][1], "None", "it stands at the end")
        revisions = self.rows("SELECT ?a ?b WHERE { ?v prov:wasRevisionOf ?w . ?v prov:wasGeneratedBy ?x . ?x yuce:frame ?a . "
                              "?w prov:wasGeneratedBy ?y . ?y yuce:frame ?b . }")
        self.assertEqual(revisions, [("6", "0"), ("7", "6")])

    def test_a_record_itself_is_never_invalidated(self):
        self.assertEqual(self.rows("SELECT ?r WHERE { ?r a yuce:Record ; prov:wasInvalidatedBy ?f . }"), [])


if __name__ == "__main__":
    unittest.main()
