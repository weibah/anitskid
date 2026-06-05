# setup so u can pip install this junk

import os
from setuptools import setup, find_packages

# read readme if it exists, otherwise use a short description
readme_path = os.path.join(os.path.dirname(__file__), "README.md")
if os.path.isfile(readme_path):
    with open(readme_path, "r", encoding="utf-8") as f:
        desc = f.read()
else:
    desc = "stops skids from touching ur code"

setup(
    name="anti-skid",
    version="1.0.0",
    author="some guy",
    description="stops skids from touching ur code",
    long_description=desc,
    long_description_content_type="text/markdown",
    url="https://github.com/weibah/anitskid",
    packages=["anti_skid"],
    py_modules=["inject"],
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
            "anti-skid-inject=inject:main_inject",
        ],
    },
)
