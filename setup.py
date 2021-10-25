#!/usr/bin/env python3
from setuptools import setup, find_packages
import os

setup(
    name='edlclient',
    version='3.53',
    packages=find_packages(),
    long_description=open("README.md").read(),
    scripts=['edl','edlclient/Tools/qc_diag','edlclient/Tools/sierrakeygen','edlclient/Tools/boottodwnload','edlclient/Tools/enableadb','edlclient/Tools/fhloaderparse','edlclient/Tools/beagle_to_loader'],
    data_files = ['LICENSE','README.md'],
    long_description_content_type="text/markdown",
    url='https://github.com/bkerler/edl',
    project_urls={
        "Bug Tracker": "https://github.com/bkerler/edl/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    license='MIT License',
    install_requires=[
    'colorama',
    'docopt',
    'usb',
    'pyusb',
    'pyserial',
    'lxml',
    'pylzma',
    'pycryptodome',
    'wheel'
    ],
    author='B. Kerler',
    author_email='info@revskills.de',
    description='Qualcomm reverse engineering and flashing tools',
    python_requires=">=3.7",
    include_package_data=True,
    zip_safe=False
)
