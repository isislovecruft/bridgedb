#!/usr/bin/env python
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           Aaron Gibson   0x2C4B239DD876C9F6 <aagbsn@torproject.org>
#           Nick Mathewson 0x21194EBB165733EA <nickm@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

from __future__ import print_function

import os
import setuptools
import sys

from glob import glob

# Fix circular dependency with setup.py install
try:
    from babel.messages.frontend import compile_catalog, extract_messages
    from babel.messages.frontend import init_catalog, update_catalog
except ImportError:
    compile_catalog = extract_messages = init_catalog = update_catalog = None

# setup automatic versioning (see top-level versioneer.py file):
import versioneer
versioneer.versionfile_source = 'lib/bridgedb/_version.py'
versioneer.versionfile_build = 'bridgedb/_version.py'

# when creating a release, tags should be prefixed with 'bridgedb-', like so:
#
#     git checkout -b release-6.6.6 develop
#     [do some stuff, merge whatever, test things]
#     git tag -S bridgedb-6.6.6
#     git push tpo-common --tags
#     git checkout master
#     git merge -S --no-ff release-6.6.6
#     git checkout develop
#     git merge -S --no-ff master
#     git branch -d release-6.6.6
#
versioneer.tag_prefix = 'bridgedb-'
# source tarballs should unpack to a directory like 'bridgedb-6.6.6'
versioneer.parentdir_prefix = 'bridgedb-'

pkgpath = os.path.join('lib', 'bridgedb')

# Repo directory that contains translations; this directory should contain
# both uncompiled translations (.po files) as well as compiled ones (.mo
# files). We only want to install the .mo files.
repo_i18n = os.path.join(pkgpath, 'i18n')

# The list of country codes for supported languages will be stored as a list
# variable, ``_supported``, in this file, so that the bridgedb packages
# __init__.py can access it:
repo_langs = os.path.join(pkgpath, '_langs.py')

# The directory containing template files and other resources to serve on the
# web server:
repo_templates = os.path.join(pkgpath, 'templates')

# The directories to install non-sourcecode resources into should always be
# given as relative paths, in order to force distutils to install relative to
# the rest of the codebase.
#
# Directory to installed compiled translations (.mo files) into:
install_i18n = os.path.join('bridgedb', 'i18n')

# Directory to install docs, license, and other text resources into:
install_docs = os.path.join('share', 'doc', 'bridgedb')

def get_cmdclass():
    """Get our cmdclass dictionary for use in setuptool.setup().

    This must be done outside the call to setuptools.setup() because we need
    to add our own classes to the cmdclass dictionary, and then update that
    dictionary with the one returned from versioneer.get_cmdclass().
    """
    cmdclass = {'test': runTests,
                'compile_catalog': compile_catalog,
                'extract_messages': extract_messages,
                'init_catalog': init_catalog,
                'update_catalog': update_catalog}
    cmdclass.update(versioneer.get_cmdclass())
    return cmdclass

def get_requirements():
    """Extract the list of requirements from our requirements.txt.

    :rtype: 2-tuple
    :returns: Two lists, the first is a list of requirements in the form of
        pkgname==version. The second is a list of URIs or VCS checkout strings
        which specify the dependency links for obtaining a copy of the
        requirement.
    """
    requirements_file = os.path.join(os.getcwd(), 'requirements.txt')
    requirements = []
    links=[]
    try:
        with open(requirements_file) as reqfile:
            for line in reqfile.readlines():
                line = line.strip()
                if line.startswith('#'):
                    continue
                elif line.startswith(
                        ('https://', 'git://', 'hg://', 'svn://')):
                    links.append(line)
                else:
                    requirements.append(line)

    except (IOError, OSError) as error:
        print(error)

    return requirements, links

def get_supported_langs():
    """Get the paths for all compiled translation files.

    The two-letter country code of each language which is going to be
    installed will be added to a list, and this list will be written to
    :attr:`repo_langs`, so that lib/bridgedb/__init__.py can store a
    package-level attribute ``bridgedb.__langs__``, which will be a list of
    any languages which were installed.

    Then, the paths of the compiled translations files are added to
    :ivar:`data_files`. These should be included in the ``data_files``
    parameter in :func:`~setuptools.setup` in order for setuptools to be able
    to tell the underlying distutils ``install_data`` command to include these
    files.

    See http://docs.python.org/2/distutils/setupscript.html#installing-additional-files
    for more information.

    :ivar list supported: A list of two-letter country codes, one for each
        language we currently provide translations support for.
    :ivar list lang_dirs: The directories (relative or absolute) to install
        the compiled translation file to.
    :ivar list lang_files: The paths to compiled translations files, relative
        to this setup.py script.
    :rtype: list
    :returns: Two lists, ``lang_dirs`` and ``lang_files``.
    """
    supported = []
    lang_dirs = []
    lang_files = []

    for lang in os.listdir(repo_i18n):
        if lang.endswith('templates'):
            continue
        supported.append(lang)
        lang_dirs.append(os.path.join(install_i18n, lang))
        lang_files.append(os.path.join(repo_i18n, lang,
                                       'LC_MESSAGES', 'bridgedb.mo'))
    supported.sort()

    # Write our list of supported languages to 'lib/bridgedb/_langs.py':
    new_langs_lines = []
    with open(repo_langs, 'r') as langsfile:
        for line in langsfile.readlines():
            if line.startswith('supported'):
                # Change the 'supported' list() into a set():
                line = "supported = set(%s)\n" % supported
            new_langs_lines.append(line)
    with open(repo_langs, 'w') as newlangsfile:
        for line in new_langs_lines:
            newlangsfile.write(line)

    return lang_dirs, lang_files

def get_template_files():
    """Return the paths to any web resource files to include in the package.

    :rtype: list
    :returns: Any files in :attr:`repo_templates` which match one of the glob
        patterns in :ivar:`include_patterns`.
    """
    include_patterns = ['*.html',
                        '*.txt',
                        '*.asc',
                        'assets/*.png',
                        'assets/*.svg',
                        'assets/css/*.css',
                        'assets/font/*.woff',
                        'assets/font/*.ttf',
                        'assets/font/*.svg',
                        'assets/font/*.eot']
    template_files = []

    for include_pattern in include_patterns:
        pattern = os.path.join(repo_templates, include_pattern)
        matches = glob(pattern)
        template_files.extend(matches)

    return template_files

def get_data_files(filesonly=False):
    """Return any hard-coded data_files which should be distributed.

    This is necessary so that both the distutils-derived :class:`installData`
    class and the setuptools ``data_files`` parameter include the same files.
    Call this function with ``filesonly=True`` to get a list of files suitable
    for giving to the ``package_data`` parameter in ``setuptools.setup()``.
    Or, call it with ``filesonly=False`` (the default) to get a list which is
    suitable for using as ``distutils.command.install_data.data_files``.

    :param bool filesonly: If true, only return the locations of the files to
        install, not the directories to install them into.
    :rtype: list
    :returns: If ``filesonly``, returns a list of file paths. Otherwise,
        returns a list of 2-tuples containing: one, the directory to install
        to, and two, the files to install to that directory.
    """
    data_files = []
    doc_files = ['README', 'TODO', 'LICENSE', 'requirements.txt']
    lang_dirs, lang_files = get_supported_langs()
    template_files = get_template_files()

    if filesonly:
        data_files.extend(doc_files)
        for lst in lang_files, template_files:
            for filename in lst:
                if filename.startswith(pkgpath):
                    # The +1 gets rid of the '/' at the beginning:
                    filename = filename[len(pkgpath) + 1:]
                    data_files.append(filename)
    else:
        data_files.append((install_docs, doc_files))
        for ldir, lfile in zip(lang_dirs, lang_files):
            data_files.append((ldir, [lfile,]))

    #[sys.stdout.write("Added data_file '%s'\n" % x) for x in data_files]

    return data_files


class runTests(setuptools.Command):
    # Based on setup.py from mixminion, which is based on setup.py
    # from Zooko's pyutil package, which is in turn based on
    # http://mail.python.org/pipermail/distutils-sig/2002-January/002714.html
    description = "Run unit tests"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        build = self.get_finalized_command('build')
        self.build_purelib = build.build_purelib
        self.build_platlib = build.build_platlib

    def run(self):
        self.run_command('build')
        old_path = sys.path[:]
        sys.path[0:0] = [self.build_purelib, self.build_platlib]
        try:
            testmod = __import__("bridgedb.Tests", globals(), "", [])
            testmod.Tests.main()
        finally:
            sys.path = old_path


# If there is an environment variable BRIDGEDB_INSTALL_DEPENDENCIES=0, it will
# disable checking for, fetching, and installing BridgeDB's dependencies with
# easy_install.
#
# Setting BRIDGEDB_INSTALL_DEPENDENCIES=0 is *highly* recommended, because
# easy_install is a security nightmare.  Automatically installing dependencies
# is enabled by default, however, because this is how all Python packages are
# supposed to work.
if bool(int(os.environ.get("BRIDGEDB_INSTALL_DEPENDENCIES", 1))):
    requires, deplinks = get_requirements()
else:
    requires, deplinks = [], []


setuptools.setup(
    name='bridgedb',
    version=versioneer.get_version(),
    description='Backend systems for distribution of Tor bridge relays',
    author='Nick Mathewson',
    author_email='nickm at torproject dot org',
    maintainer='Isis Agora Lovecruft',
    maintainer_email='isis@torproject.org 0xA3ADB67A2CDB8B35',
    url='https://www.torproject.org',
    download_url='https://gitweb.torproject.org/bridgedb.git',
    package_dir={'': 'lib'},
    packages=['bridgedb',
              'bridgedb.email',
              'bridgedb.parse',
              'bridgedb.test'],
    scripts=['scripts/bridgedb',
             'scripts/get-tor-exits'],
    extras_require={'test': ["sure==1.2.2",
                             "coverage==3.7.1",
                             "leekspin==1.1.4"]},
    zip_safe=False,
    cmdclass=get_cmdclass(),
    include_package_data=True,
    install_requires=requires,
    dependency_links=deplinks,
    package_data={'bridgedb': get_data_files(filesonly=True)},
    exclude_package_data={'bridgedb': ['*.po', '*.pot']},
    message_extractors={pkgpath: [
        ('**.py', 'python', None),
        ('templates/**.html', 'mako', None),
        ('public/**', 'ignore', None)]},
)
# XXX I think we don't need the 'public/**' babel.messages.frontend.method_map
# anymore... 2013-10-15 --isis
