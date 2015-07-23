import os
import sys
from setuptools import setup, find_packages

PY2 = sys.version_info[0] == 2

# Read package meta-data from the containing directory.

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, "README.rst")) as f:
    README = f.read()

with open(os.path.join(here, "CHANGES.txt")) as f:
    CHANGES = f.read()

with open(os.path.join(here, "dev-requirements.txt")) as f:
    requires = (ln.strip() for ln in f)
    test_requires = [ln for ln in requires if ln and not ln.startswith("#")]

if sys.version_info < (2, 7):
    test_requires.append("unittest2")

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

REQUIREMENTS = [
    "requests>=2.4.2",
    "cryptography",
    "PyBrowserID",
    "hawkauthlib",
    "six"
]

if PY2:
    OPENSSL_REQUIREMENTS = [
        "pyopenssl",
        "ndg-httpsclient",
        "pyasn1"
    ]
else:
    OPENSSL_REQUIREMENTS = []

setup(name="PyFxA",
      version=VERSION,
      description="Firefox Accounts client library for Python",
      long_description=README + "\n\n" + CHANGES,
      classifiers=[
          "Intended Audience :: Developers",
          "Programming Language :: Python",
          "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
      ],
      entry_points={
          'httpie.plugins.auth.v1': [
              'httpie_fxa-browserid = fxa.plugins.requests:FxABrowserIDPlugin'
          ]
      },
      license="MPLv2.0",
      author="Mozilla Services",
      author_email="services-dev@mozilla.org",
      url="https://github.com/mozilla/PyFxA",
      keywords="firefox accounts authentication",
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=REQUIREMENTS,
      extras_require={
          'openssl': OPENSSL_REQUIREMENTS
      },
      tests_require=test_requires,
      test_suite="fxa")
