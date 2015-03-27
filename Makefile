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
	virtualenv --no-site-packages --python=`which python` --distribute $(VENVDIR)
	$(INSTALL) --upgrade Distribute pip
	$(INSTALL) -r ./dev-requirements.txt
	$(PYTHON) ./setup.py develop
	touch $(VENVDIR)/COMPLETE

.PHONY: test
test: $(BINDIR)/flake8 $(BINDIR)/nosetests $(BINDIR)/coverage
	$(BINDIR)/flake8 ./fxa
	$(BINDIR)/coverage erase
	$(BINDIR)/coverage run $(BINDIR)/nosetests -s ./fxa
	$(BINDIR)/coverage report --include="*fxa*"

.PHONY: coverage
coverage: htmlcov/index.html
	$(BINDIR)/coverage report --include="*fxa*"

htmlcov/index.html: .coverage
	$(BINDIR)/coverage html --include="*fxa*"

.coverage: $(BINDIR)/coverage
	$(BINDIR)/coverage run $(BINDIR)/nosetests ./fxa

$(BINDIR)/flake8: $(VENVDIR)/COMPLETE
	$(INSTALL) -U --force-reinstall flake8

$(BINDIR)/nosetests: $(VENVDIR)/COMPLETE
	$(INSTALL) -U --force-reinstall nose

$(BINDIR)/coverage: $(VENVDIR)/COMPLETE
	$(INSTALL) -U --force-reinstall coverage

.PHONY: pyshell
pyshell: $(VENVDIR)/COMPLETE
	$(PYTHON)

.PHONY: clean
clean:
	rm -rf htmlcov .coverage dist

.PHONY: clobber
clobber: clean
	rm -rf $(VENVDIR)
