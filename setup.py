from glob import glob
from pathlib import Path
from setuptools import setup, find_packages

setup(
    name="dllproxy",
    version="0.1",
    description="Generate And Build a Windows DLL Proxy For Any DLL",
    license="MIT",
    readme="README.md",
    author="Gil Alpert",
    author_email="alpertgil@gmail.com",
    url="https://github.com/gilgoolon/dllproxy",
    packages=find_packages(),
    install_requires=[
        "pefile"
    ],
    entry_points={
        "console_scripts": [
            "dllproxy-generate = dllproxy:dllproxy_generate"
        ]
    },
    include_package_data=True,
    package_data={"dllproxy": ["template/**/**"]}
)
