from pathlib import Path
import typing as t

dirname = Path(__file__).parent
examples = dirname/"examples"

def extract_label(line: str) -> str:
    _, rest = line.split('label={')
    label, _ = rest.split("},caption")
    return label

listing_labels = [extract_label(line) for line in open(dirname/"paper.tex") if line.startswith("\\lstinputlisting")]

headings = (
    "Name",
    "Listing",
    "Direct-style",
    "Fork-style",
)
rows = []
for label in listing_labels:
    dir = examples/label
    direct_wc = len(list((dir/"direct.py").open()))
    fork_path = dir/"fork.py"
    fork_wc = len(list(fork_path.open())) if fork_path.exists() else "n/a"
    rows.append((
        label,
        "\\ref{" + label + "}",
        direct_wc,
        fork_wc,
    ))
def line(row: t.List) -> str:
    return " & ".join(str(x) for x in row) + " \\\\"
print('\\begin{tabular}{' + ''.join('r' for _ in rows[0]) + '}')
print('\\hline')
print(line(headings))
print('\\hline')
for row in rows:
    print(line(row))
print('\\hline')
print('\\end{tabular}')
