#!/usr/bin/env python3
"""Setup configuration for TracePort package."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="traceport",
    version="1.0.0",
    author="PasinduW-sketch",
    description="High-performance Python-based Network Port Scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/PasinduW-sketch/TracePort",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "tabulate>=0.9.0",
    ],
    entry_points={
        "console_scripts": [
            "traceport=traceport.cli:main",
            "traceport-gui=traceport.gui:main",
        ],
    },
)
