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

import versioneer


pkgpath = 'bridgedb'

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
repo_templates = os.path.join(pkgpath, 'https', 'templates')

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
    cmdclass = {'test': Trial,
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
                if line.startswith(('git+', 'hg+', 'svn+')):
                    line = line[line.index('+') + 1:]
                if line.startswith(
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
    :attr:`repo_langs`, so that bridgedb/__init__.py can store a
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

    # Write our list of supported languages to 'bridgedb/_langs.py':
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
                        'assets/font/*.eot',
                        'assets/js/*.js',
                        'assets/images/*.svg']
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


class Trial(setuptools.Command):
    """Twisted Trial setuptools command.

    Based on the setuptools Trial command in Zooko's Tahoe-LAFS, as well as
    https://github.com/simplegeo/setuptools-trial/ (which is also based on the
    Tahoe-LAFS code).

    Pieces of the original implementation of this 'test' command (that is, for
    the original pyunit-based BridgeDB tests which, a long time ago, in a
    galaxy far far away, lived in bridgedb.Tests) were based on setup.py from
    Nick Mathewson's mixminion, which was based on the setup.py from Zooko's
    pyutil package, which was in turn based on
    http://mail.python.org/pipermail/distutils-sig/2002-January/002714.html.

    Crusty, old-ass Python, like hella wut.
    """
    description = "Run Twisted Trial-based tests."
    user_options = [
        ('debug', 'b', ("Run tests in a debugger. If that debugger is pdb, will "
                        "load '.pdbrc' from current directory if it exists.")),
        ('debug-stacktraces', 'B', "Report Deferred creation and callback stack traces"),
        ('debugger=', None, ("The fully qualified name of a debugger to use if "
                             "--debug is passed (default: pdb)")),
        ('disablegc', None, "Disable the garbage collector"),
        ('force-gc', None, "Have Trial run gc.collect() before and after each test case"),
        ('jobs=', 'j', "Number of local workers to run, a strictly positive integer"),
        ('profile', None, "Run tests under the Python profiler"),
        ('random=', 'Z', "Run tests in random order using the specified seed"),
        ('reactor=', 'r', "Which reactor to use"),
        ('reporter=', None, "Customize Trial's output with a reporter plugin"),
        ('rterrors', 'e', "Realtime errors: print out tracebacks as soon as they occur"),
        ('spew', None, "Print an insanely verbose log of everything that happens"),
        ('testmodule=', None, "Filename to grep for test cases (-*- test-case-name)"),
        ('tbformat=', None, ("Specify the format to display tracebacks with. Valid "
                             "formats are 'plain', 'emacs', and 'cgitb' which uses "
                             "the nicely verbose stdlib cgitb.text function")),
        ('unclean-warnings', None, "Turn dirty reactor errors into warnings"),
        ('until-failure', 'u', "Repeat a test (specified by -s) until it fails."),
        ('without-module=', None, ("Fake the lack of the specified modules, separated "
                                   "with commas")),
    ]
    boolean_options = ['debug', 'debug-stacktraces', 'disablegc', 'force-gc',
                       'profile', 'rterrors', 'spew', 'unclean-warnings',
                       'until-failure']

    def initialize_options(self):
        self.debug = None
        self.debug_stacktraces = None
        self.debugger = None
        self.disablegc = None
        self.force_gc = None
        self.jobs = None
        self.profile = None
        self.random = None
        self.reactor = None
        self.reporter = None
        self.rterrors = None
        self.spew = None
        self.testmodule = None
        self.tbformat = None
        self.unclean_warnings = None
        self.until_failure = None
        self.without_module = None

    def finalize_options(self):
        build = self.get_finalized_command('build')
        self.build_purelib = build.build_purelib
        self.build_platlib = build.build_platlib

    def run(self):
        self.run_command('build')
        old_path = sys.path[:]
        sys.path[0:0] = [self.build_purelib, self.build_platlib]

        result = 1
        try:
            result = self.run_tests()
        finally:
            sys.path = old_path
            raise SystemExit(result)

    def run_tests(self):
        # We do the import from Twisted inside the function instead of the top
        # of the file because since Twisted is a setup_requires, we can't
        # assume that Twisted will be installed on the user's system prior, so
        # if we don't do the import here, then importing from this plugin will
        # fail.
        from twisted.scripts import trial

        if not self.testmodule:
            self.testmodule = "bridgedb.test"

        # Handle parsing the trial options passed through the setuptools
        # trial command.
        cmd_options = []
        for opt in self.boolean_options:
            if getattr(self, opt.replace('-', '_'), None):
                cmd_options.append('--%s' % opt)

        for opt in ('debugger', 'jobs', 'random', 'reactor', 'reporter',
                    'testmodule', 'tbformat', 'without-module'):
            value = getattr(self, opt.replace('-', '_'), None)
            if value is not None:
                cmd_options.extend(['--%s' % opt, value])

        config = trial.Options()
        config.parseOptions(cmd_options)
        config['tests'] = [self.testmodule,]

        trial._initialDebugSetup(config)
        trialRunner = trial._makeRunner(config)
        suite = trial._getSuite(config)

        # run the tests
        if self.until_failure:
            test_result = trialRunner.runUntilFailure(suite)
        else:
            test_result = trialRunner.run(suite)

        if test_result.wasSuccessful():
            return 0  # success
        return 1      # failure


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
    package_dir={'bridgedb': 'bridgedb'},
    packages=['bridgedb',
              'bridgedb.email',
              'bridgedb.https',
              'bridgedb.parse'],
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
    message_extractors={
        pkgpath: [
            ('**.py', 'python', None),
            ('https/templates/**.html', 'mako', None),
        ]
    },
)
