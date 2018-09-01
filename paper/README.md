
To compile:

    $ latex attestation.tex
    $ bibtex attestation
    $ latex attestation.tex
    $ latex attestation.tex

If you desire the PDF format:

    $ dvipdfm attestation.dvi

To compile the Chinese translation, you will need CTex. On Ubuntu you
can install it with:

    $ sudo apt-get install texlive-lang-chinese

Then run this:

    $ xelatex Attestation-on-Ethereum-translation-CN.tex

Which should generate a file `Attestation-on-Ethereum-translation-CN.pdf`.
