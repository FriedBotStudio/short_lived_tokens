__version__ = ''
import os
import setuptools

curr_dir = os.path.curdir

with open('short_lived_tokens/VERSION') as version_file:
    __version__ = version_file.read().strip()

short_description = "Short lived tokens v{}".format(__version__)

with open("README.md", "r") as fh:
    long_description = fh.read()


setuptools.setup(
    name='short_lived_tokens',
    version=__version__,
    author='Tushar Srivastava',
    author_email='tusharsrivastava@friedbotstudio.com',
    description=short_description,
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=['short_lived_tokens', 'short_lived_tokens.django'],
    package_dir={'short_lived_tokens': '.'},
    package_data={
        '': ['short_lived_tokens/VERSION'],
    },
    include_package_data=True,
    install_requires=['typing_extensions', 'pycryptodome'],
    url="https://github.com/FriedBotStudio/short_lived_tokens",
    project_urls={
        "Bug Tracker": "https://github.com/FriedBotStudio/short_lived_tokens/issues",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Framework :: Django",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
