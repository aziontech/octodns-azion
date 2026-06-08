#!/usr/bin/env python

from setuptools import find_packages, setup


def descriptions():
    with open('README.md') as fh:
        ret = fh.read()
        first = ret.split('\n', 1)[0].replace('#', '')
        return first, ret


def version():
    with open('octodns_azion/__init__.py') as fh:
        for line in fh:
            if line.startswith('__version__'):
                return line.split("'")[1]
    return 'unknown'


description, long_description = descriptions()

tests_require = ('pytest>=9.0.3,<10.0.0', 'pytest-cov>=7.1.0', 'pytest-network')

setup(
    author='Marcus Grando',
    author_email='marcus.grando@azion.com',
    description=description,
    extras_require={
        'dev': tests_require
        + (
            # black has yearly style changes, bump manually when ready
            # https://black.readthedocs.io/en/stable/the_black_code_style/index.html#stability-policy
            'black>=26.5.1,<27.0.0',
            'build>=1.5.0',
            'isort>=8.0.1',
            'pyflakes>=3.2.0',
            'readme_renderer[md]>=44.0',
            'twine>=6.2.0',
        ),
        'test': tests_require,
    },
    install_requires=('octodns>=1.19.0', 'requests>=2.34.2'),
    license='MIT',
    long_description=long_description,
    long_description_content_type='text/markdown',
    name='octodns-azion',
    packages=find_packages(),
    python_requires='>=3.10',
    tests_require=tests_require,
    url='https://github.com/aziontech/octodns-azion',
    version=version(),
)
