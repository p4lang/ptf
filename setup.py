from distutils.core import setup

long_description = """
PTF is a Python based dataplane test framework. It is based on unittest, which is included in the standard Python distribution.

This document is meant to provide an introduction to the framework, discuss the basics of running tests and to provide examples of how to add tests.

Most of the code was taken from the OFTest framework. However, PTF focuses on the dataplane and is independent of OpenFlow. We also made a few additions to oftest.
"""

setup (name='ptf',
    version='0.9',
    py_modules=[],
    package_dir={'': 'src'},
    packages=['ptf'],
    description='PTF is a Python based dataplane test framework.',
    long_description=long_description,
    author='Guohan Lu',
    author_email='lguohan@gmail.com',
    url='https://github.com/p4lang/ptf',
    license='Apache license',
    platforms='UNIX',
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache License',
        'Operating System :: POSIX',
        'Operating System :: MacOS :: MacOS X',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Software Development :: Quality Assurance',
        'Topic :: Software Development :: Testing',
        'Topic :: System',
        'Topic :: System :: Archiving :: Packaging',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Shells',
        'Topic :: System :: Software Distribution',
        'Topic :: Terminals',
    ],
)
