import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="loxws",
    version="0.0.53",
    author="tjsmithuk",
    author_email="https://github.com/grimbouk/loxws",
    description="Loxone Client",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/grimbouk/loxws",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'pycryptodome>=3.14.1',
        'aiohttp>=3.9.1'
    ]
)