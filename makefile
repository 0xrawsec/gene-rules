
DST=compiled.gen

all: compile

verify:
	$(GENE) -r ./rules -verify

test: verify
	echo "Testing Rules"
	echo "# Rules Coverage" > tests.md
	echo  >> tests.md
	./scripts/tester.py ./scripts/tester.conf | sed "s/$$/\n/" | tee -a tests.md

compile: test verify
	$(GENE) -r ./rules -dump '.*' > $(DST)
	shasum -a 256 $(DST) > $(DST).sha256
