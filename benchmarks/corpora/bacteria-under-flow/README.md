# Bacteria under flow: three papers, 2017 to 2024

Three open-access papers on bacteria settling and growing on surfaces under fluid flow. This is a corpus for withdrawals and for
links between papers: claims whose quotes come from two or three of them. Each file is an excerpt of a paper, converted from the
JATS XML of Europe PMC to Markdown. Its header names the paper, the licence and what was changed.

| File | Paper | Published |
|---|---|---|
| `B_thomen2017.md` | Thomen P, Robert J, Monmeyran A, Bitbol A-F, Douarche C, Henry N. Bacterial biofilm under flow: First a physical struggle to stay, then a matter of breathing. PLoS One 12:e0175197. doi:10.1371/journal.pone.0175197, PMC5389662 | 12 April 2017 |
| `A_rossy2019.md` | Rossy T, Nadell CD, Persat A. Cellular advective-diffusion drives the emergence of bacterial surface colonization patterns and heterogeneity. Nat Commun 10:2471. doi:10.1038/s41467-019-10469-6, PMC6554397 | 6 June 2019 |
| `C_hubert2024.md` | Hubert A, Tabuteau H, Farasin J, et al., Le Borgne T. Fluid flow drives phenotypic heterogeneity in bacterial growth and adhesion on surfaces. Nat Commun 15:6161. doi:10.1038/s41467-024-49997-1, PMC11263347 | 22 July 2024 |

- **Licence.** All three papers are published under the Creative Commons Attribution 4.0 International licence (CC BY 4.0),
  https://creativecommons.org/licenses/by/4.0/. Their copyright stays with their authors. This repository reproduces the
  excerpts with attribution, to pin the bytes of a benchmark.
- **What was changed**, as each header says:
  - converted from JATS XML to plain Markdown;
  - sections selected: the abstract, the introduction, the results, the discussion and some methods sections;
  - figures, tables and the reference list omitted; citations in the text are kept as numbers, such as `[21]`;
  - in C, two parts are kept on purpose: Table 1 (its shear regimes), as a Markdown table after the paragraph that cites it,
    and the three reference entries that the paragraph on erosion cites (21, 34, 35; 21 is paper A, 35 is paper B).
- **Sizes and SHA-256:**
  - `A_rossy2019.md`: 28,794 bytes, `e86d281b…b90d01`;
  - `B_thomen2017.md`: 40,998 bytes, `f350479e…f26e23`;
  - `C_hubert2024.md`: 36,828 bytes, `4de06f5b…3f18dd`;
  - 106,620 bytes in all.
- **How the kernel cuts them.** Each Markdown heading opens a reading section, and a section holds at most 6000 bytes. That
  gives 7 sections for A, 10 for B and 8 for C. Tables, formulas and non-ASCII characters such as μ, − and ± do not move a cut.
- **`questions.json`** holds the run's three questions with their topics. A topic is the stem of a word of the question itself.
  The kernel shows the topics to the readers, and picks the claims of an answer's window by them.
- **`withdrawal.json`**: two steps, both applied. 2A withdraws a clause of B, 2B a sentence of A.
- **`manifest.json`** names, for each file, its size, SHA-256, git blob id, publication date and paper (DOI, PMC id, licence).
  The kernel's document ids come from the manifest's source repository, commit and path. The papers are in no git repository,
  so the manifest names this repository (`OrganeticSphere/yuce`), the commit of it that holds the three files, and their paths
  from the repository's root. A run of this corpus takes the repository's root as `--repo`.
- **`reports.txt`** gives the files in publication order, and **`document_order.json`** the kernel's document ids in that order.
- **`checklist.md`** says how the run is graded.
- **The reference** was fixed before the run, with two addenda. It holds the papers' facts, the links between papers, the traps,
  and for each withdrawal what must fall and what must stand. `benchmarks/PREREGISTRATION_CROSS_BIO.md` names the three files by
  SHA-256; they are published under `../gold/` after the run. The reference was written by an AI model from the papers' text, not
  by a domain expert.
- **The withdrawals are a synthetic intervention.** Neither paper is retracted, and the run makes no claim that either is wrong.

`benchmarks/test_cross_bio_corpus.py` checks:
- the bytes of the three files, their attribution headers, and the publication order;
- the manifest against the files and, in a clone of this repository, that the pinned commit holds them; the document order;
- that both withdrawn passages sit at their offsets, once each, and inside one reading section of the kernel;
- the questions and their topics, and the plan.
