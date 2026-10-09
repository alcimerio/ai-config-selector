# Profile transactions

Profile transactions preserve stored capability selections and their local history.
This glossary names the distinction between publication and its acknowledgment.

## Language

**Profile**:
A stored selection of common capabilities and explicit target overlays, or a
legacy target-bound selection.

**Profile transaction**:
One authorized conditional change to a stored Profile and its local history.

**Transaction outcome**:
The returned certainty of a Profile transaction: not committed, committed, or
unknown, with a separate indication of whether recovery is required.

**Profile completion**:
The command's acknowledgment of a returned Profile transaction outcome.
A failed acknowledgment does not change a committed outcome.
