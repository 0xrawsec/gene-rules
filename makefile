
DST=compiled.gen

all: compile

verify:
	gene -r ./rules -verify

test: verify
	echo "Testing Rules"
	echo "# Rules Coverage" > tests.md
	echo  >> tests.md
	./scripts/tester.py ./scripts/tester.conf | sed "s/$$/\n/" | tee -a tests.md

compile: test verify
	gene -r ./rules -dump '.*' > $(DST)
	shasum -a 256 $(DST) > $(DST).sha256
