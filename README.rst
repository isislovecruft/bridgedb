**********************************************************
BridgeDB |Latest Version| |Build Status| |Coverage Status|
**********************************************************

BridgeDB is a collection of backend servers used to distribute `Tor Bridges
<https://www.torproject.org/docs/bridges>`__. Currently, it mainly consists of
a webserver with `an HTTPS interface <https://bridges.torproject.org>`__,
`an email responder <mailto:bridges@torproject.org>`__, and an SQLite database.

.. |Latest Version| image:: https://pypip.in/version/bridgedb/badge.svg?style=flat
   :target: https://pypi.python.org/pypi/bridgedb/
.. |Build Status| image:: https://travis-ci.org/isislovecruft/bridgedb.svg
   :target: https://travis-ci.org/isislovecruft/bridgedb
.. |Coverage Status| image:: https://coveralls.io/repos/isislovecruft/bridgedb/badge.png?branch=develop
   :target: https://coveralls.io/r/isislovecruft/bridgedb?branch=develop


.. image:: doc/sphinx/source/_static/bay-bridge.jpg
   :scale: 80%
   :align: center


.. contents::
   :backlinks: entry


=====================
What are Tor Bridges?
=====================

`Tor Bridges <https://www.torproject.org/docs/bridges>`__ are special
Tor relays which are not listed in the public relay directory. They are
used to help circumvent `censorship <https://ooni.torproject.org>`__ by
providing users with connections to the public relays in the Tor
network.

Tor Bridges are different from normal relays in another important way:
they can run what are called *Pluggable* *Transports*.

-----------------------------
What's a Pluggable Transport?
-----------------------------

A `Pluggable
Transport <https://www.torproject.org/docs/pluggable-transports.html.en>`__
is a program which is *pluggable* — meaning that it is meant to work
with lots of other anonymity and censorship circumvention software, not
just Tor — and is a *transport* — meaning that it transports your
internet traffic, usually in a way which makes it look different. For
example,
`Obfsproxy <https://www.torproject.org/projects/obfsproxy.html.en>`__ is
a Pluggable Transport which disguises your traffic by adding an
obfuscating layer of encryption.

---------------------
So how do I use this?
---------------------

Well, probably, you don't. But if you're looking for bridges, you can
use `the web interface <https://bridges.torproject.org>`__ of the
BridgeDB instance deployed by the Tor Project, which has instructions on
getting the Pluggable Transports-capable Tor Browser Bundle, as well as
instructions for getting extra Bridges.


================
Maintainer Setup
================

If you'd like to hack on BridgeDB, you might wish to read BridgeDB's
`developer documentation <https://pythonhosted.org/bridgedb/>`__.  The rest of
this document mainly concerns mainenance and installation instructions.

-----------------------------
Dependencies and installation
-----------------------------

BridgeDB requires the following OS-level dependencies:

-  python>=2.7
-  python-dev
-  build-essential
-  gnupg (preferrably, gnupg2)
-  OpenSSL>=1.0.1g
-  `SQLite3 <http://www.maxmind.com/app/python>`__
-  `MaxMind GeoIP <https://www.maxmind.com/en/geolocation_landing>`__
-  libgeoip-dev
-  geoip-database
-  `python-setuptools <https://pypi.python.org/pypi/setuptools>`__
-  libjpeg-dev

As well as any Python dependencies in the ``requirements.txt`` file.

.. note: There are additional dependencies for things like running the test
    suites, building BridgeDB's developer documentation, etc. Read on for more
    info if you wish to enable addition features.


------------------
Deploying BridgeDB
------------------

BridgeDB should work with or without a Python virtualenv.

-  Install Python 2.7, and other OS-level dependencies. On Debian, you
   can do::

         sudo apt-get install build-essential openssl python python-dev \
           python-setuptools sqlite3 gnupg2 libgeoip-dev geoip-database


-  Install Pip 1.3.1 or later. Debian has this version, but if for some
   reason that or a newer version isn't available, the easiest way to
   install a newer Pip is to use the Pip development teams's `getpip
   script <https://raw.github.com/pypa/pip/master/contrib/get-pip.py>`__::

         wget https://raw.github.com/pypa/pip/master/contrib/get-pip.py
         sudo python get-pip.py


-  **(virtualenv installs only)** Use Pip to install virtualenv and
   `virtualenvwrapper <https://virtualenvwrapper.readthedocs.org>`__::

         sudo pip install --upgrade virtualenv virtualenvwrapper


-  **(virtualenv installs only)** Configure virtualenvwrapper and create a
   virtualenv for BridgeDB::

         WORKON_HOME=${HOME}/.virtualenvs
         export WORKON_HOME
         mkdir -p $WORKON_HOME
         source $(which virtualenvwrapper.sh)
         git clone https://git.torproject.org/bridgedb.git && cd bridgedb
         mkvirtualenv -a $PWD -r requirements.txt --unzip-setuptools --setuptools bridgedb

   From now on, to use BridgeDB's virtualenv, just do ``$ workon bridgedb``
   (after sourcing virtualenvwrapper.sh, as before). To exit the virtualenv
   without exiting the shell, do ``$ deactivate``.


-  **(virtualenv installs only)** To install, set PYTHONPATH to include the
   root directory of the virtualenv::

         export PYTHONPATH=$PYTHONPATH:${VIRTUAL_ENV}/lib/python2.7/site-packages


-  Then, proceed as usual::

         python setup.py install --record installed-files.txt


============================
Enabling additional features
============================

------------
Translations
------------

**Using New Translations**:

This should be done when newly completed translations are available in
Transifex.

Piece of cake. Running ``maint/get-completed-translations`` will take
care of cloning *only* the ``bridgedb_completed`` branch of Tor's
`translations repo <https://gitweb.torproject.org/translation.git>`__
and placing all the updated files in their correct locations.

-------

**Requesting Translations for Altered/Added Source Code**:

This should be done whenever any of the strings requiring translation --
``_("the ones inside the weird underscore function, like this")`` -- are
changed, or new ones are added. See ``lib/bridgedb/strings.py``.

Translations for Tor Project repos are kept `in a separate
repo <https://gitweb.torproject.org/translation.git>`__. You'll need to
extract the strings from BridgeDB's source code into .pot templates, and
place these .po files into the ``translation`` repo in the ``bridgedb``
branch. After than the .po files should be put into Transifex (don't ask
me how this works…) and translated. After the translations are complete,
the finished .po files should be placed into the ``bridgedb_completed``
branch.

-  To extract all strings from BridgeDB's source::

         python setup.py extract_messages

   A .pot file will be created in ./i18n/templates/bridgedb.pot


-  Initialise catalogs for each desired language::

         python setup.py init_catalog -l LANG

   where ``LANG`` is the 2 or 4 letter country-code, eg. 'es'. If you've
   already initialised a particular language, do instead::

         python setup.py update_catalog


-------

--------------
Enabling HTTPS
--------------

Create a self-signed certificate with::

         scripts/make-ssl-cert

Or, place an existing certificate in the path specified in bridgedb.conf
by the ``HTTPS_CERT_FILE`` option, and a private key where
``HTTPS_KEY_FILE`` points to. The defaults are 'cert' and 'privkey.pem',
respectively.


------------------------
Enabling CAPTCHA Support
------------------------

BridgeDB has two ways to use CAPTCHAs on webpages. The first uses reCaptcha_,
an external Google service (this requires an account with them), which
BridgeDB fetches the CAPTCHAs images from for each incoming request from a
client. The second method uses a local cache of pre-made CAPTCHAs, created by
scripting Gimp using gimp-captcha_. The latter cannot easily be run on
headless server, unfortunately, because Gimp requires an X server to be
installed.

.. _reCaptcha: https://www.google.com/recaptcha
.. _gimp-captcha: https://github.com/isislovecruft/gimp-captcha


**reCaptcha**

To enable fetching CAPTCHAs from the reCaptcha API server, set these
options in bridgedb.conf::

      RECAPTCHA_ENABLED
      RECAPTCHA_PUB_KEY
      RECAPTCHA_SEC_KEY

-------

**gimp-captcha**

To enable using a local cache of CAPTCHAs, set the following options::

      GIMP_CAPTCHA_ENABLED
      GIMP_CAPTCHA_DIR
      GIMP_CAPTCHA_HMAC_KEYFILE
      GIMP_CAPTCHA_RSA_KEYFILE

-------

--------------------
GnuPG email signing:
--------------------

In your ``bridgedb.conf`` file, make sure that::

      EMAIL_GPG_SIGNING_ENABLED = True

and edit the following option to add the full fingerprint of the GnuPG key
that should be used to by BridgeDB to sign outgoing emails::

      EMAIL_GPG_PRIMARY_KEY_FINGERPRINT

The key specified by ``EMAIL_GPG_PRIMARY_KEY_FINGERPRINT`` can be a master
key, or a subkey (with or without the private portions of its corresponding
master key), but it **must** be inside the ``secring.gpg`` and ``pubring.gpg``
keyrings inside the directory specified in the ``bridgedb.conf`` option::

      EMAIL_GPG_HOMEDIR

If the key has requires a passphrase for signing, you'll also need to set
either of::

      EMAIL_GPG_PASSPHRASE
      EMAIL_GPG_PASSPHRASE_FILE


----------------------------------------------------------
Preventing already-blocked bridges from being distributed:
----------------------------------------------------------

Uncomment or add ``COUNTRY_BLOCK_FILE`` to your bridgedb.conf. This file
should contain one bridge entry per line, in the format::

      fingerprint <bridge fingerprint> country-code <country code>

If the ``COUNTRY_BLOCK_FILE`` file is present, bridgedb will filter
blocked bridges from the responses it gives to clients requesting
bridges.


================
Testing BridgeDB
================

Before running to any of BridgeDB's test suites, make sure you have the
additional dependencies in the Pip requirements file,
``.test.requirements.txt`` installed::

      pip install -r .test.requirements.txt

To create a bunch of fake bridge descriptors to test BridgeDB, do::

      bridgedb mock [-n NUMBER_OF_DESCRIPTORS]

Note that you will need to install
`leekspin <https://pypi.python.org/pypi/leekspin>`__ in order to run the
``bridgedb mock`` command. See ``doc/HACKING.md`` for details.

And finally, to run the test suites, do::

      make coverage

If you just want to run the tests, and don't care about code coverage
statistics, see the ``bridgedb trial`` and ``bridgedb test`` commands.


================
Running BridgeDB
================

To run BridgeDB, simply make any necessary changes to bridgedb.conf, and do::

      bridgedb

And remember that all files/directories in ``bridgedb.conf`` are assumed
relative to the runtime directory. By default, BridgeDB uses the current
working directory; you can, however specify an a different runtime
directory::

      bridgedb -r /srv/bridges.torproject.org/run

Make sure that the files and directories referred to in bridgedb.conf
exist. However, many of them, if not found, will be touched on disk so
that attempts to read/write from/to them will not raise excessive
errors.


----------------------------------------------
Reloading Bridges From Their Descriptor Files:
----------------------------------------------

When you have new lists of bridges from the Bridge Authority, replace
the old files and do::

      bridgedb --reload

Or just give it a SIGHUP::

      kill -s SIGHUP `cat .../run/bridgedb.pid`


---------------------------------------------------
To extract bucket files of all unallocated bridges:
---------------------------------------------------

Edit the configuration file value ``FILE_BUCKETS`` according to your
needs. For example, the following is a possible configuration::

      FILE_BUCKETS = { "name1": 10, "name2": 15, "foobar": 3 }

This configuration for buckets would result in 3 files being created for
bridge distribution: name1-2010-07-17.brdgs, name2-2010-07-17.brdgs and
foobar-2010-07-17.brdgs. The first file would contain 10 bridges from
BridgeDB's 'unallocated' pool. The second file would contain 15 bridges
from the same pool and the third one similarly 3 bridges. These files
can then be handed out to trusted parties via mail or fed to other
distribution mechanisms such as Twitter.

To dump all buckets to their files, send BridgeDB a ``SIGUSR1`` signal
by doing::

      kill -s SIGUSR1 `cat .../run/bridgedb.pid`


=========================
Using a BridgeDB Instance
=========================

Obviously, you'll have to feed it bridge descriptor files from a
BridgeAuthority. There's currently only one BridgeAuthority in the entire
world, but Tor Project is, of course, very interested in adding support for
multiple BridgeAuthorities so that we can scale our own network, and make it
easier for individual and organisations who wish to run a lot of Tor bridge
relays have an easier time distributing those bridges themselves (if they wish
to do so). If you'd like to fund our work on this, please contact
tor-dev@lists.torproject.org!

----------------------------------
Accessing the HTTPS User Interface
----------------------------------

Just connect to the appropriate port. (See the ``HTTPS_PORT`` and
``HTTP_UNENCRYPTED_PORT`` options in the ``bridgedb.conf`` file.)

The HTTPS interface for our BridgeDB instance can be found `here
<https://bridges.torproject.org>`__.


----------------------------------
Accessing the Email User Interface
----------------------------------

Any mail sent to the ``EMAIL_PORT`` with a destination username as defined by
the ``EMAIL_USERNAME`` configuration option (the default is ``'bridge'``,
e.g. bridges@...) and sent from an ``@riseup.net``, ``@gmail.com``, or
``@yahoo.com`` address (by default, but configurable with the
``EMAIL_DOMAINS`` option).

You can email our BridgeDB instance `here <mailto:bridges@torproject.org>`__.

=================
Contact & Support
=================

Send your questions, patches, and suggestions to
`the tor-dev mailing list <mailto:tor-dev@lists.torproject.org>`__
or `isis <mailto:isis@torproject.org>`__.
