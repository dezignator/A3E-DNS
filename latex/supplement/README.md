# A3E-DNS LaTeX supplement

The typeset supplement that accompanies Chapter 6 of the thesis. It
contains the experiment descriptions, the notation table, the figure
captions, and the S1–S9 result tables. The tables are `\input{}`
from `tables/`, which is populated by the Python result-table
generator; the rest of the supplement is hand-written.

## Building

The supplement requires a working LaTeX installation with `pdflatex`,
`booktabs`, `siunitx`, `hyperref` and `xcolor`. On a Debian-family
system:

```bash
sudo apt-get install texlive-latex-recommended \
    texlive-latex-extra texlive-fonts-recommended texlive-science
