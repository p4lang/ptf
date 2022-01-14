import os
from setuptools import setup
project_root = os.path.dirname(os.path.realpath(__file__))

with open(os.path.join(project_root, 'README.md')) as readme_file:
    readme = readme_file.read()

with open("requirements.txt", "r") as req:
    requirements = []
    for l in req.readlines():
        requirements.append(l.rstrip())

setup(
    name='ptf',
    version='0.9.3',
    description='PTF is a Python based dataplane test framework.',
    long_description=readme,
    long_description_content_type="text/markdown",
    author='Antonin Bas',
    author_email='antonin@barefootnetworks.com',
    url='https://github.com/p4lang/ptf',
    packages=[
        'ptf', 'ptf.platforms',
    ],
    package_dir={'': 'src'},
    scripts=[
        'ptf',
        'ptf_nn/ptf_nn_agent.py'
    ],
    install_requires=requirements,
    zip_safe=False,
    license='Apache License',
    keywords='ptf',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
    ]
)
