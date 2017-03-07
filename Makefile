XML2RFC = xml2rfc
DOCUMENTS = nsec5 vrf
OUTPUTS=$(foreach doc,$(DOCUMENTS),$(doc).txt $(doc).html)

.PHONY: all
all: $(OUTPUTS)

%.txt: %.xml
	$(XML2RFC) -o $@ --text $^

%.html: %.xml
	$(XML2RFC) -o $@ --html $^

.PHONY: clean
clean:
	rm -f $(OUTPUTS)

release_doc = $(foreach format,xml txt html,cp -vf $(1).$(format) $(2).$(format);)
release: $(OUTPUTS)
	$(foreach doc,$(DOCUMENTS),$(call release_doc,$(doc),$(shell grep 'docName=' $(doc).xml | grep -o '"[^"]*"' | sed 's@"@@g' | grep draft)))
