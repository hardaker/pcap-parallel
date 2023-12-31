import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pcap-parallel",
    version="0.1",
    author="Wes Hardaker",
    author_email="opensource@hardakers.net",
    description="A tool for processing pcap files in parallel",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hardaker/pcap-parallel",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=[
        "dpkt",
    ],
)
