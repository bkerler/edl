#!/usr/bin/env python3
from setuptools import setup, find_packages
import os

setup(
    name='edlclient',
    version='3.62',
    packages=find_packages(),
    long_description=open("README.md").read(),
    entry_points={
        'console_scripts': [
            'edl=edlclient.edl:run',
            'qc_diag=edlclient.Tools.qc_diag:main',
            'sierrakeygen=edlclient.Tools.sierrakeygen:main',
            'boottodwnload=edlclient.Tools.boottodwnload:main',
            'enableadb=edlclient.Tools.enableadb:main',
            'fhloaderparse=edlclient.Tools.fhloaderparse:main',
            'beagle_to_loader=edlclient.Tools.beagle_to_loader:main',
        ],
    },
    data_files = ['LICENSE','README.md'],
    long_description_content_type="text/markdown",
    url='https://github.com/bkerler/edl',
    project_urls={
        "Bug Tracker": "https://github.com/bkerler/edl/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPlv3 License",
        "Operating System :: OS Independent",
    ],
    license='GPLv3 License',
    install_requires=[
    'colorama',
    'docopt',
    'usb',
    'pyusb',
    'pyserial',
    'lxml',
    'pylzma',
    'pycryptodome',
    'wheel',
    'Exscript',
    'requests',
    'passlib'
    ],
    author='B. Kerler',
    author_email='info@revskills.de',
    description='Qualcomm reverse engineering and flashing tools',
    python_requires=">=3.7",
    include_package_data=True,
    zip_safe=False
)
