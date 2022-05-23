FORMATS := html txt
TARGETS := $(foreach ext,$(FORMATS),draft-paragon-paseto-rfc-02.$(ext))

.PHONY: all clean publish
all: $(TARGETS)

publish: all
	mkdir -p pages
	cp $(TARGETS) pages/

clean:
	rm -f $(TARGETS) draft-paragon-paseto-rfc-02.xml
	rm -rf pages

draft-paragon-paseto-rfc-02.xml: paseto.md
	mmark $< > $@

%.txt: %.xml
	xml2rfc --text $<

%.html: %.xml
	xml2rfc --html $<
