.PHONY: build test sample

build:
	mkdir -p build && cobc -x -free -o build/passwd-audit src/passwd_audit.cob

test: build
	sh tests/test.sh

sample: build
	mkdir -p docs site
	build/passwd-audit examples/passwd examples/shadow > docs/sample-output.txt; true
	build/passwd-audit examples/passwd examples/shadow --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "passwd-audit" "Audits /etc/passwd and /etc/shadow style files: extra UID 0 accounts, empty passwords, weak hashes, system accounts with shells. COBOL." "Synthetic account files, fake hashes."
