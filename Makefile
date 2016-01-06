VENVDIR = ./build/venv
BINDIR = $(VENVDIR)/bin
PYTHON = $(BINDIR)/python
PIP = $(BINDIR)/pip
INSTALL = $(PIP) install

.PHONY: all
all:	build test

.PHONY: build
build: $(VENVDIR)/COMPLETE
$(VENVDIR)/COMPLETE: dev-requirements.txt
	virtualenv --python=`which python` $(VENVDIR)
	$(INSTALL) --upgrade pip
	$(INSTALL) -r ./dev-requirements.txt
	$(INSTALL) -e .
	touch $(VENVDIR)/COMPLETE

.PHONY: test
test: $(BINDIR)/flake8 $(BINDIR)/nosetests
	$(BINDIR)/nosetests --with-mocha-reporter --with-coverage --cover-package=fxa ./fxa
	$(BINDIR)/flake8 ./fxa

$(BINDIR)/flake8: $(VENVDIR)/COMPLETE
	$(INSTALL) -U --force-reinstall flake8

$(BINDIR)/nosetests: $(VENVDIR)/COMPLETE
	$(INSTALL) -U --force-reinstall nose nose-cov nose-mocha-reporter

.PHONY: pyshell
pyshell: $(VENVDIR)/COMPLETE
	$(PYTHON)

.PHONY: clean
clean:
	rm -rf htmlcov .coverage dist

dist-clean:
	rm -fr build/

.PHONY: clobber
clobber: clean
	rm -rf $(VENVDIR)
