#!/usr/bin/env python3
import setuptools
import warnings
from setuptools.extension import Extension
from Cython.Build import cythonize

__version__ = "0.0.0"

# because of our plugin architecture (and sanity), don't import strelka, but try to scan
# out the version from the top-level __init__.py instead
with open("strelka/__init__.py", "r") as fh:
    for line in fh:
        if line.startswith("__version__"):
            exec(line)
            break
    else:
        warnings.warn("unable to extract strelka version from strelka/__init__.py")

setuptools.setup(
    name="strelka",
    version=__version__,
    author="Target Brands, Inc.",
    description="strelka: container-based file analysis at scale",
    license="Apache 2.0",
    zip_safe=False,
    # find all our packages, but don't consider tests
    packages=setuptools.find_packages(exclude=["tests"]),
    package_dir={"": "."},
    # these are the sane ways of calling ourself once installed
    scripts=["bin/strelka-backend"],
    entry_points={
        "console_scripts": [
            "strelka = strelka.__main__:main",
        ]
    },
    # compile our XAR archive helper module
    ext_modules=cythonize([
        Extension(
            "strelka.auxiliary.xar",
            ["strelka/auxiliary/xar/xar.pyx"],
            libraries=["xar"],
        ),
    ]),
)
