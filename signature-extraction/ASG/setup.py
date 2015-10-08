#!/usr/bin/env python

from setuptools import setup, Extension, find_packages

asg_engine = Extension(
    'asg.CppAsgEngine.asg_engine_ext',
    [
        'asg/CppAsgEngine/AbstractTrieNode.cpp',
        'asg/CppAsgEngine/AsgEngine.cpp',
        'asg/CppAsgEngine/Dendrogram.cpp',
        'asg/CppAsgEngine/LocalAlignment.cpp',
        'asg/CppAsgEngine/RegexExtractorLCSS.cpp',
        'asg/CppAsgEngine/SmlLrgSigExtrct.cpp',
        'asg/CppAsgEngine/SuricataRuleMaker.cpp',
        'asg/CppAsgEngine/Trie.cpp',
        'asg/DetectorReports/DetectorReport.cpp',
    ],
    define_macros=[
        ('BOOST_ALL_DYN_LINK', 1),
    ],
    libraries=[
        'boost_python',
        'boost_log',
        'boost_regex',
        'crypto++',
        'fasguardfilter',
    ],
    extra_compile_args=[
        '-std=c++11',
    ],
)

detector_xmt = Extension(
    'asg.DetectorReports.detector_xmt_ext',
    [
        'asg/DetectorReports/DetectorReport.cpp',
    ],
    libraries=[
        'boost_python',
    ],
)

setup(
    name='fasguardasg',
    version='1.0',
    description='Automatic Signature Generator',
    author='FASGuard project',
    author_email='fasguard@bbn.com',
    packages=find_packages(),
    ext_modules=[
        asg_engine,
        detector_xmt,
    ],
    scripts=[
        'ASG.py',
        'Detector2Stix.py',
        'LCSS.py',
    ],
    install_requires=[
        'dpkt',
        'lxml',
        'pylibpcap',
        'stix',
    ],
    package_data={
        'asg': [
            'asg-joined.properties',
            'asg-snippet.properties',
            'asg.properties',
        ],
    },
)
