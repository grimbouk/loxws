import os
from pathlib import Path

import setuptools

ROOT = Path(__file__).parent


def read_long_description():
    return (ROOT / "README.md").read_text(encoding="utf-8")


def read_version():
    namespace = {}
    version_file = ROOT / "loxws" / "_version.py"
    exec(version_file.read_text(encoding="utf-8"), namespace)
    return os.getenv("LOXWS_VERSION", namespace["__version__"])


setuptools.setup(
    name="loxws",
    version=read_version(),
    author="tjsmithuk",
    author_email="tjsmithuk@clamfish.com",
    description="Loxone Client",
    long_description=read_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/grimbouk/loxws",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "pycryptodome>=3.14.1",
        "aiohttp>=3.9.1",
    ],
)
