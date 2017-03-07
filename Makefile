# Original makefile from https://github.com/martinthomson/i-d-template

# Edited by wkumari to remove a bunch of the extra stuff I'll never use.
# Then more by tale to suit workflow of other drafts

# The following tools are used by this file.
# All are assumed to be on the path, but you can override these
# in the environment, or command line.

# Mandatory:
#   https://pypi.python.org/pypi/xml2rfc
xml2rfc ?= xml2rfc

# If you are using markdown files:
#   https://github.com/cabo/kramdown-rfc2629
kramdown-rfc2629 ?= kramdown-rfc2629

# If you are using outline files:
#   https://github.com/Juniper/libslax/tree/master/doc/oxtradoc
oxtradoc ?= oxtradoc.in

# For sanity checkout your draft:
#   https://tools.ietf.org/tools/idnits/
idnits ?= idnits

# For generating PDF:
#   https://www.gnu.org/software/enscript/
enscript ?= enscript
#   http://www.ghostscript.com/
ps2pdf ?= ps2pdf 

## Targets

.PHONY: latest txt html pdf submit diff clean

latest: txt html
txt: nsec5.txt vrf.txt
html: nsec5.html vrf.html

idnits: nsec5.txt vrf.txt
	$(idnits) nsec5.txt
	$(idnits) vrf.txt

clean:
	-rm -f {nsec5,vrf}.{txt,html,pdf} index.html
	-rm -f *.diff.html
	-rm -f nsec5.xml

commit: latest
	@echo "Committing and pushing to github. Run 'make tag' to add and push a tag."
	read -p "Commit message: " msg; \
	git commit -a -m "$$msg";
	@git push

tag:
	@echo "Current tags:"
	git tag
	@echo
	@read -p "Tag message (e.g: Version-00): " tag; \
	git tag -a $$tag -m $$tag
	@git push --tags

## Recipes

.INTERMEDIATE: $(draft).raw.txt
%.xml: %.md
	$(kramdown-rfc2629) $< > $@

%.xml: %.org
	$(oxtradoc) -m outline-to-xml -n "$@" $< > $@

%.txt: %.xml
	$(xml2rfc) $< -o $@ --text

%.raw.txt: %.xml
	$(xml2rfc) $< -o $@ --raw

%.html: %.xml
	$(xml2rfc) $< -o $@ --html

%.pdf: %.txt
	$(enscript) --margins 76::76: -G -q -p - $^ | $(ps2pdf) - $@
