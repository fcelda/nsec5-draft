XML2RFC=xml2rfc

nsec5.txt: nsec5.xml
	$(XML2RFC) -o $@ --text $^
