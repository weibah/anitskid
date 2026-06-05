# setup so u can pip install this junk

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    desc = f.read()

setup(
    name="anti-skid",
    version="1.0.0",
    author="some guy",
    description="stops skids from touching ur code",
    long_description=desc,
    long_description_content_type="text/markdown",
    url="https://github.com/weibah/anitskid",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "dev": ["pytest>=7.0", "pytest-cov>=4.0"],
    },
    entry_points={
        "console_scripts": [
            "anti-skid-gen=anti_skid.cli:generate_manifest_cli",
        ],
    },
)