"""setup module."""

from distutils.core import setup
from pathlib import Path
import re
from setuptools import find_packages

name = "intel_sgx_ra"

version = re.search(
    r"""(?x)
    __version__
    \s=\s
    \"
    (?P<number>.*)
    \"
    """,
    Path(f"src/{name}/__init__.py").read_text(),
)

setup(
    name=name,
    version=version["number"],
    url="https://cosmian.com",
    license="MIT",
    author="Cosmian Tech",
    author_email="tech@cosmian.com",
    description="Intel SGX Remote Attestation verification library",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    long_description=Path("README.md").read_text(),
    long_description_content_type="text/markdown",
    zip_safe=False,
    install_requires=["requests>=2.28.1,<3.0.0", "cryptography>=39.0.0,<40.0.0"],
    entry_points={
        "console_scripts": [
            "sgx-ra-verify = intel_sgx_ra.cli.verify:run",
            "sgx-ra-utils = intel_sgx_ra.cli.utils:run",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    setup_requires=["wheel"],
    tests_require=["pytest>=7.2.1,<7.3.0"],
    package_data={"intel_sgx_ra": ["py.typed"]},
    include_package_data=True,
)
