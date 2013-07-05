## BridgeDB
-----------

BridgeDB is a collection of backend servers used to distribute
[Tor Bridges](https://www.torproject.org/docs/bridges). It currently consists
of a webserver with [an HTTPS interface](https://bridges.torproject.org), an
email responder, and an SQLite database.

#### What are Tor Bridges?
[Tor Bridges](https://www.torproject.org/docs/bridges) are special Tor relays
which are not listed in the public relay directory. They are used to help
circumvent [censorship](https://ooni.torproject.org) by providing users with
connections to the public relays in the Tor network.

Tor Bridges are different from normal relays in another important way: they
can run what are called *Pluggable* *Transports*.

#### What's a Pluggable Transport?
A
[Pluggable Transport](https://www.torproject.org/docs/pluggable-transports.html.en)
is a program which is *pluggable* — meaning that it is meant to work with lots
of other anonymity and censorship circumvention software, not just Tor — and
is a *transport* — meaning that it transports your internet traffic, usually
in a way which makes it look different. For example,
[Obfsproxy](https://www.torproject.org/projects/obfsproxy.html.en) is a
Pluggable Transport which disguises your traffic by adding an obfuscating
layer of encryption.

#### So how do I use this?
Well, probably, you don't. But if you're looking for bridges, you can use
[BridgeDB's web interface](https://bridges.torproject.org), which has
instructions on getting the Pluggable Transports Tor Browser Bundle, as well
as instructions for getting extra Bridges.


## Maintainer Setup

### Dependencies and installation
BridgeDB requires the following OS-level dependencies:

 - Python>=2.6
 - OpenSSL>=1.0.1e
 - [SQLite3](http://www.maxmind.com/app/python)
 - [MaxMind GeoIP](https://www.maxmind.com/en/geolocation_landing)
 - [python-setuptools](https://pypi.python.org/pypi/setuptools)

As well as the following Python dependencies (from ./requirements.txt):

    Babel==0.9.6
    BeautifulSoup==3.2.1
    Mako==0.8.1
    MarkupSafe==0.18
    Twisted>=13.0.0
    argparse>=1.2.1
    distribute>=0.6.46
    ipaddr>=2.1.10
    pyOpenSSL>=0.13
    pygeoip>=0.2.6
    pygpgme==0.3
    recaptcha>=1.0rc1
    recaptcha-client>=1.0.6
    wsgiref>=0.1.2
    zope.interface>=4.0.5

### Deploying BridgeDB in a Python virtualenv

 - Install Python 2.6 or later, and other OS-level dependencies. On Debian,
   you can do:

       sudo apt-get install python openssl sqlite3 tor-geoip

 - Install Pip 1.3.1 or later. Debian sid has this version, but if you're
   tracking a different release, the easiest way to install a newer Pip is to
   use the Pip development teams's
   [getpip script](https://raw.github.com/pypa/pip/master/contrib/get-pip.py):

       wget https://raw.github.com/pypa/pip/master/contrib/get-pip.py
       sudo python get-pip.py

 - Use Pip to install virtualenv and [virtualenvwrapper](https://virtualenvwrapper.readthedocs.org):

       sudo pip install --upgrade virtualenv virtualenvwrapper

 - Configure virtualenvwrapper and create a virtualenv for Bridgedb:

       WORKON_HOME=${HOME}/.virtualenvs
       export WORKON_HOME
       mkdir -p $WORKON_HOME
       source $(which virtualenvwrapper.sh)
       git clone https://git.torproject.org/bridgedb.git && cd bridgedb
       mkvirtualenv -a $PWD -r requirements.txt --unzip-setuptools \
           --setuptools bridgedb
 
   From now on, to use BridgeDB's virtualenv, just do ```$ workon bridgedb```
   (after sourcing virtualenvwrapper.sh, as before). To exit the virtualenv
   without exiting the shell, do ```$ deactivate```.

 - To run unit tests:

       python setup.py test

 - To install BridgeDB:

       python setup.py install


### Enabling additional features:

#### Translations
 - To extract all strings from BridgeDB's source:

       python setup.py extract_messages

   A .pot file will be created in ./i18n/templates/bridgedb.pot
 - Initialise catalogs for each desired language:

       python setup.py init_catalog -l LANG

   where ```LANG``` is the 2 or 4 letter country-code, eg. 'es'.
 - Edit strings in ./i18n/LANG/bridgedb.po, and then convert them to binary
   format:

       python setup.py compile_catalog

   Don't forget to reinstall BridgeDB to update the templates!

       python setup.py install

 - To generate translation files, and then install them, do:

       python setup.py trans && python setup.py install_data

#### Enabling HTTPS
Create a self-signed certificate with:

     openssl req -x509 -new -nodes > cert

Or, place an existing certificate in the path specified in bridgedb.conf by
the ```HTTPS_CERT_FILE``` option, and a private key where ```HTTPS_KEY_FILE```
points to. The defaults are 'cert' and 'privkey.pem', respectively.

#### CAPTCHAs
To enable Captchas on the webserver interface, set the options in
bridgedb.conf:

    RECAPTCHA_ENABLED
    RECAPTCHA_PUB_KEY
    RECAPTCHA_PRIV_KEY
    
A [recaptcha.net](https://www.google.com/recaptcha) account is required.

#### GnuPG email signing
Add these two options to your bridgedb.conf:

     EMAIL_GPG_SIGNING_ENABLED
     EMAIL_GPG_SIGNING_KEY
    
The former may be either True or False, and the latter must point to the
ascii-armored private key file. The keyfile must not be passphrase protected.

#### Preventing already-blocked bridges from being distributed
Uncomment or add ```COUNTRY_BLOCK_FILE``` to your bridgedb.conf. This file
should contain one bridge entry per line, in the format:
 
    fingerprint <bridge fingerprint> country-code <country code>

If the ```COUNTRY_BLOCK_FILE``` file is present, bridgedb will filter blocked
bridges from the responses it gives to clients requesting bridges.

#### Updating the SQL schema
Make sure that SQLite3 is installed. (You should have installed it already
during the setup and installation stage.) To update, do:

    sqlite3 path/to/bridgedist.db.sqlite

Enter the following commands at the ```sqlite>``` prompt: 

    CREATE TABLE BlockedBridges ( id INTEGER PRIMARY KEY NOT NULL, hex_key, blocking_country);
    CREATE INDEX BlockedBridgesBlockingCountry on BlockedBridges(hex_key);
    CREATE TABLE WarnedEmails ( email PRIMARY KEY NOT NULL, when_warned);
    CREATE INDEX WarnedEmailsWasWarned on WarnedEmails ( email );
    REPLACE INTO Config VALUES ( 'schema-version', 2 );
 

## Running BridgeDB
To run BridgeDB, simply make any necessary changes to bridgedb.conf, and do:

    python -m TorBridgeDB -c bridgedb.conf

When you have new lists of bridges, replace the old files and send the process
a SIGHUP.

Make sure that the files and directories referred to in bridgedb.conf
exist. However, many of them, if not found, will be touched on disk so that
attempts to read/write from/to them will not raise excessive errors.

#### To extract bucket files of all unallocated bridges:
Edit the configuration file value ```FILE_BUCKETS``` according to your
needs. For example, the following is a possible configuration:

    FILE_BUCKETS = { "name1": 10, "name2": 15, "foobar": 3 }

This configuration for buckets would result in 3 files being created for
bridge distribution: name1-2010-07-17.brdgs, name2-2010-07-17.brdgs and
foobar-2010-07-17.brdgs. The first file would contain 10 bridges from
BridgeDB's 'unallocated' pool. The second file would contain 15 bridges from
the same pool and the third one similarly 3 bridges. These files can then be
handed out to trusted parties via mail or fed to other distribution mechanisms
such as twitter.

#### To use with HTTPS:
Just connect to the appropriate port.

#### To use with email:
Any mail sent to the email port with a subject or a single line _exactly_
equal to "get bridges" will get answered, assuming the domain is okay.

### Support
Send your questions to aagbsn@torproject.org.
