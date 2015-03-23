XML2RFC=xml2rfc

.PHONY: all clean release

all: nsec5.txt nsec5.html

clean:
	rm -f nsec5.txt nsec5.html

release: DRAFT=$(shell grep 'docName=' nsec5.xml | grep -o '"[^"]*"' | sed 's@"@@g' | grep draft)
release: nsec5.txt nsec5.html
	cp nsec5.xml "$(DRAFT).xml"
	cp nsec5.txt "$(DRAFT).txt"
	cp nsec5.html "$(DRAFT).html"

nsec5.txt: nsec5.xml
	$(XML2RFC) -o $@ --text $^

nsec5.html: nsec5.xml
	$(XML2RFC) -o $@ --html $^
