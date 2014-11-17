
import os
import sys
from setuptools import setup, find_packages

# Read package meta-data from the containing directory.

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, "README.rst")) as f:
    README = f.read()

with open(os.path.join(here, "CHANGES.txt")) as f:
    CHANGES = f.read()

with open(os.path.join(here, "requirements.txt")) as f:
    requires = (ln.strip() for ln in f)
    requires = [ln for ln in requires if ln and not ln.startswith("#")]

if sys.version_info < (2, 7):
    requires.append("unittest2")

# Read the version number from the module source code.
# To do so, we parse out all lines up to the ones defining __version__ and
# execute them, then grab the resulting value of the __version__ variable.

info = {}
try:
    lines = []
    with open("fxa/__init__.py") as f:
        for ln in f:
            lines.append(ln)
            if "__version__" in ln:
                break
        for ln in f:
            lines.append(ln)
            if "__version__" not in ln:
                break
    exec("".join(lines), info)
except Exception:
    pass
VERSION = info.get("__version__", "0.0.0dev")


setup(name="PyFxA",
      version=VERSION,
      description="Firefox Accounts client library for Python",
      long_description=README + "\n\n" + CHANGES,
      classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
      ],
      license="MPLv2.0",
      author="Mozilla Services",
      author_email="services-dev@mozilla.org",
      url="https://github.com/mozilla/PyFxA",
      keywords="firefox accounts authentication",
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=requires,
      test_suite="fxa")
