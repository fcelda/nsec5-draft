XML2RFC=xml2rfc

.PHONY: all clean

all: nsec5.txt nsec5.html

clean:
	rm -f nsec5.txt nsec5.html

nsec5.txt: nsec5.xml
	$(XML2RFC) -o $@ --text $^

nsec5.html: nsec5.xml
	$(XML2RFC) -o $@ --html $^
