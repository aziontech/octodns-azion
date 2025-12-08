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

# pytest<9.0 required for Python 3.9 compatibility
tests_require = ('pytest>=8.0.0,<9.0.0', 'pytest-cov>=6.0.0', 'pytest-network')

setup(
    author='Marcus Grando',
    author_email='marcus.grando@azion.com',
    description=description,
    extras_require={
        'dev': tests_require
        + (
            # black has yearly style changes, bump manually when ready
            # https://black.readthedocs.io/en/stable/the_black_code_style/index.html#stability-policy
            'black>=24.3.0,<26.0.0',
            'build>=1.0.0',
            'isort>=5.13.0',
            'pyflakes>=3.2.0',
            'readme_renderer[md]>=44.0',
            'twine>=6.0.0',
        ),
        'test': tests_require,
    },
    install_requires=('octodns>=1.12.0', 'requests>=2.32.5'),
    license='MIT',
    long_description=long_description,
    long_description_content_type='text/markdown',
    name='octodns-azion',
    packages=find_packages(),
    python_requires='>=3.9',
    tests_require=tests_require,
    url='https://github.com/aziontech/octodns-azion',
    version=version(),
)
