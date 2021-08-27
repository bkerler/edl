#!/usr/bin/env python3
from setuptools import setup, find_packages
import os

setup(
    name='edl',
    version='3.5',
    packages=find_packages(),
    long_description=open("README.md").read(),
    scripts=['edl.py','diag.py','modem/sierrakeygen.py','modem/boottodwnload.py','modem/enableadb.py','Loaders/fhloaderparse.py','Loaders/beagle_to_loader.py'],
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
