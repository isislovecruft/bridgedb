# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2007-2014, The Tor Project, Inc.
#             (c) 2013-2014, Isis Lovecruft
#             (c) 2007-2014, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

"""crypto - BridgeDB general cryptographic utilities.

Module Overview:
````````````````
::
  crypto
   |_getGPGContext() - Get a pre-configured GPGME context.
   |_getHMAC() - Compute an HMAC with some key for some data.
   |_getHMACFunc() - Get a callable for producing HMACs with the given key.
   |_getKey() - Load the master HMAC key from a file, or create a new one.
   |_getRSAKey() - Load an RSA key from a file, or create a new one.
   |_gpgSignMessage() - Sign a message string according to a GPGME context.
   |_writeKeyToFile() - Write to a file readable only by the process owner.
   |
   \_SSLVerifyingContextFactory - OpenSSL.SSL.Context factory which verifies
      |                           certificate chains and matches hostnames.
      |_getContext() - Retrieve an SSL context configured for certificate
      |                verification.
      |_getHostnameFromURL() - Parses the hostname from the request URL.
      \_verifyHostname() - Check that the cert CN matches the request
                           hostname.
::
"""

from __future__ import absolute_import
from __future__ import unicode_literals

import gpgme
import hashlib
import hmac
import io
import logging
import os
import re
import urllib

import OpenSSL

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from twisted.internet import ssl


#: The hash digest to use for HMACs.
DIGESTMOD = hashlib.sha1


class RSAKeyGenerationError(Exception):
    """Raised when there was an error creating an RSA keypair."""

class PythonicGpgmeError(Exception):
    """Replacement for ``gpgme.GpgmeError`` with understandable error info."""

class LessCrypticGPGMEError(Exception):
    """Holds interpreted info on source/type of a ``gpgme.GpgmeError``."""

    def __init__(self, gpgmeError, *args):
        self.interpretCrypticGPGMEError(gpgmeError)
        super(LessCrypticGPGMEError, self).__init__(self.message)

    def interpretCrypticGPGMEError(self, gpgmeError):
        """Set our ``message`` attribute with a decoded explanation of the
        GPGME error code received.

        :type gpgmeError: ``gpgme.GpgmeError``
        :param gpgmeError: An exception raised by the gpgme_ module.

        .. _gpgme: https://bazaar.launchpad.net/~jamesh/pygpgme/trunk/view/head:/src/pygpgme-error.c
        """
        try:
            errorSource, errorCode, errorMessage = gpgmeError.args
        except (AttributeError, ValueError):
            self.message = "Could not get error code from gpgme.GpgmeError!"
            return

        if errorCode and errorSource:
            try:
                sources = gpgmeErrorTranslations[str(errorSource)]
            except KeyError:
                sources = ['UNKNOWN']
            sources = ', '.join(sources).strip(',')

            try:
                names = gpgmeErrorTranslations[str(errorCode)]
            except KeyError:
                names = ['UNKNOWN']
            names = ', '.join(names).strip(',')

            self.message = "GpgmeError: {0} stemming from {1}: '{2}'""".format(
                names, sources, str(errorMessage))

def writeKeyToFile(key, filename):
    """Write **key** to **filename**, with ``0400`` permissions.

    If **filename** doesn't exist, it will be created. If it does exist
    already, and is writable by the owner of the current process, then it will
    be truncated to zero-length and overwritten.

    :param bytes key: A key (or some other private data) to write to
        **filename**.
    :param str filename: The path of the file to write to.
    :raises: Any exceptions which may occur.
    """
    logging.info("Writing key to file: %r" % filename)
    flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT | getattr(os, "O_BIN", 0)
    fd = os.open(filename, flags, 0400)
    os.write(fd, key)
    os.fsync(fd)
    os.close(fd)

def getRSAKey(filename, bits=2048):
    """Load the RSA key stored in **filename**, or create and save a new key.

    >>> from bridgedb import crypto
    >>> keyfile = 'doctest_getRSAKey'
    >>> message = "The secret words are Squeamish Ossifrage."
    >>> keypair = crypto.getRSAKey(keyfile, bits=2048)
    >>> (secretkey, publickey) = keypair
    >>> encrypted = publickey.encrypt(message)
    >>> assert encrypted != message
    >>> decrypted = secretkey.decrypt(encrypted)
    >>> assert message == decrypted


    If **filename** already exists, it is assumed to contain a PEM-encoded RSA
    private key, which will be read from the file. (The parameters of a
    private RSA key contain the public exponent and public modulus, which
    together comprise the public key ― ergo having two separate keyfiles is
    assumed unnecessary.)

    If **filename** doesn't exist, a new RSA keypair will be created, and the
    private key will be stored in **filename**, using :func:`writeKeyToFile`.

    Once the private key is either loaded or created, the public key is
    extracted from it. Both keys are then input into PKCS#1 RSAES-OAEP cipher
    schemes (see `RFC 3447 §7.1`__) in order to introduce padding, and then
    returned.

    .. __: https://tools.ietf.org/html/rfc3447#section-7.1

    :param str filename: The filename to which the secret parameters of the
        RSA key are stored in.
    :param int bits: If no key is found within the file, create a new key with
        this bitlength and store it in **filename**.
    :rtype: tuple of ``Crypto.Cipher.PKCS1_OAEP.PKCS1OAEP_Cipher``
    :returns: A 2-tuple of ``(privatekey, publickey)``, which are PKCS#1
        RSAES-OAEP padded and encoded private and public keys, forming an RSA
        keypair.
    """
    filename = os.path.extsep.join([filename, 'sec'])
    keyfile = os.path.join(os.getcwd(), filename)

    try:
        fh = open(keyfile, 'rb')
    except IOError:
        logging.info("Generating %d-bit RSA keypair..." % bits)
        secretKey = RSA.generate(bits, e=65537)

        # Store a PEM copy of the secret key (which contains the parameters
        # necessary to create the corresponding public key):
        secretKeyPEM = secretKey.exportKey("PEM")
        writeKeyToFile(secretKeyPEM, keyfile)
    else:
        logging.info("Secret RSA keyfile %r found. Loading..." % filename)
        secretKey = RSA.importKey(fh.read())
        fh.close()

    publicKey = secretKey.publickey()

    # Add PKCS#1 OAEP padding to the secret and public keys:
    sk = PKCS1_OAEP.new(secretKey)
    pk = PKCS1_OAEP.new(publicKey)

    return (sk, pk)

def getKey(filename):
    """Load the master key stored in ``filename``, or create a new key.

    If ``filename`` does not exist, create a new 32-byte key and store it in
    ``filename``.

    >>> import os
    >>> from bridgedb import crypto
    >>> name = 'doctest_getKey'
    >>> os.path.exists(name)
    False
    >>> k1 = crypto.getKey(name)
    >>> os.path.exists(name)
    True
    >>> open(name).read() == k1
    True
    >>> k2 = crypto.getKey(name)
    >>> k1 == k2
    True

    :param string filename: The filename to store the secret key in.
    :rtype: bytes
    :returns: A byte string containing the secret key.
    """
    try:
        fh = open(filename, 'rb')
    except IOError:
        logging.debug("getKey(): Creating new secret key.")
        key = OpenSSL.rand.bytes(32)
        writeKeyToFile(key, filename)
    else:
        logging.debug("getKey(): Secret key file found. Loading...")
        key = fh.read()
        fh.close()
    return key

def getHMAC(key, value):
    """Return the HMAC of **value** using the **key**."""
    h = hmac.new(key, value, digestmod=DIGESTMOD)
    return h.digest()

def getHMACFunc(key, hex=True):
    """Return a function that computes the HMAC of its input using the **key**.

    :param bool hex: If True, the output of the function will be hex-encoded.
    :rtype: callable
    :returns: A function which can be uses to generate HMACs.
    """
    h = hmac.new(key, digestmod=DIGESTMOD)
    def hmac_fn(value):
        h_tmp = h.copy()
        h_tmp.update(value)
        if hex:
            return h_tmp.hexdigest()
        else:
            return h_tmp.digest()
    return hmac_fn

def _createGPGMEErrorInterpreters():
    """Create a mapping of GPGME ERRNOs ←→ human-readable error names/causes.

    This function is called automatically when :mod:`this module
    <bridgedb.crypto>` is loaded. The resulting dictionary mapping is stored
    as :attr:`~bridgedb.crypto.gpgmeErrorTranslations`, and is used by
    :exc:`~bridgedb.crypto.LessCrypticGPGMEError`.

    :returns: A dict of::
          {str(ERRNO): [ERRORNAME, ANOTHER_ERRORNAME, …],
           …,
           str(ERRORNAME): str(ERRNO),
           …}
        for all known error numbers and error names/causes.
    """
    errorDict = {}
    errorAttrs = []

    if gpgme is not None:
        errorAttrs = dir(gpgme)

    for attr in errorAttrs:
        if attr.startswith('ERR'):
            errorName = attr
            errorCode = getattr(gpgme, attr, None)
            if errorCode is not None:
                try:
                    allErrorNames = errorDict[str(errorCode)]
                except KeyError:
                    allErrorNames = []
                allErrorNames.append(str(errorName))

                errorDict.update({str(errorCode): allErrorNames})
                errorDict.update({str(errorName): str(errorCode)})

    return errorDict

#: This is a dictionary which holds a translation of GPGME ERRNOs ←→ all known
#: names/causes for that ERRNO, and vice versa. It is created automatically,
#: via the :func:`_createGPGMEErrorInterpreters` function, when this module is
#: loaded so that :exc:`LessCrypticGPGMEError` can use it to display
#: human-readable information about why GPGME borked itself on something.
gpgmeErrorTranslations = _createGPGMEErrorInterpreters()

def getGPGContext(cfg):
    """Import a key from a file and initialise a context for GnuPG operations.

    The key should not be protected by a passphrase, and should have the
    signing flag enabled.

    :type cfg: :class:`bridgedb.persistent.Conf`
    :param cfg: The loaded config file.
    :rtype: :class:`gpgme.Context` or None
    :returns: A GPGME context with the signers initialized by the keyfile
        specified by the option EMAIL_GPG_SIGNING_KEY in bridgedb.conf, or
        None if the option was not enabled, or was unable to initialize.
    """
    try:
        # must have enabled signing and specified a key file
        if not cfg.EMAIL_GPG_SIGNING_ENABLED or not cfg.EMAIL_GPG_SIGNING_KEY:
            return None
    except AttributeError:
        return None

    keyfile = None
    ctx = gpgme.Context()

    try:
        logging.debug("Opening GPG keyfile %s..." % cfg.EMAIL_GPG_SIGNING_KEY)
        keyfile = open(cfg.EMAIL_GPG_SIGNING_KEY)
        key = ctx.import_(keyfile)

        if not len(key.imports) > 0:
            logging.debug("Unexpected result from gpgme.Context.import_(): %r"
                          % key)
            raise PythonicGpgmeError("Could not import GnuPG key from file %r"
                                     % cfg.EMAIL_GPG_SIGNING_KEY)

        fingerprint = key.imports[0][0]
        subkeyFingerprints = []
        # For some reason, if we don't do it exactly like this, we can get
        # signatures for *any* key in the current process owner's keyring
        # file:
        bridgedbKey = ctx.get_key(fingerprint)
        bridgedbUID = bridgedbKey.uids[0].uid
        logging.info("GnuPG key imported: %s" % bridgedbUID)
        logging.info("       Fingerprint: %s" % fingerprint)
        for subkey in bridgedbKey.subkeys:
            logging.info("Subkey fingerprint: %s" % subkey.fpr)
            subkeyFingerprints.append(subkey.fpr)

        ctx.armor = True
        ctx.signers = (bridgedbKey,)

        logging.debug("Testing signature created with GnuPG key...")
        testMessage = "Testing 1 2 3"
        signatureText, sigs = gpgSignMessage(ctx, testMessage)

        if not len(sigs) == 1:
            raise PythonicGpgmeError("Testing couldn't produce a signature "\
                                     "with GnuPG key: %s" % fingerprint)

        sigFingerprint = sigs[0].fpr
        if sigFingerprint in subkeyFingerprints:
            logging.info("GPG signatures will use subkey with fingerprint: %s"
                         % sigFingerprint)
        else:
            if sigFingerprint != fingerprint:
                raise PythonicGpgmeError(
                    "Test sig fingerprint '%s' not from any appropriate key!"
                    % sigFingerprint)

    except (IOError, OSError) as error:
        logging.debug(error)
        logging.error("Could not open or read from GnuPG key file %r!"
                      % cfg.EMAIL_GPG_SIGNING_KEY)
        ctx = None
    except gpgme.GpgmeError as error:
        lessCryptic = LessCrypticGPGMEError(error)
        logging.error(lessCryptic)
        ctx = None
    except PythonicGpgmeError as error:
        logging.error(error)
        ctx = None
    finally:
        if keyfile and not keyfile.closed:
            keyfile.close()

    return ctx

def gpgSignMessage(gpgmeCtx, messageString, mode=None):
    """Sign a **messageString** with a GPGME context.

    :param gpgmeCtx: A ``gpgme.Context`` initialised with the appropriate
        settings.
    :param str messageString: The message to sign.
    :param mode: The signing mode. (default: ``gpgme.SIG_MODE_CLEAR``)
    :rtype: tuple
    :returns: A 2-tuple of ``(signature, list)``, where:
        * ``signature`` is the ascii-armored signature text.
        * ``list`` is a list of ``gpgme.NewSignature``s.

    .. warning:: The returned signature text and list *may* be empty, if no
        signature was created.
    """
    if not mode:
        mode = gpgme.SIG_MODE_CLEAR

    msgFile = io.StringIO(unicode(messageString))
    sigFile = io.StringIO()
    sigList = gpgmeCtx.sign(msgFile, sigFile, mode)
    sigFile.seek(0)
    signature = sigFile.read()

    return (signature, sigList)


class SSLVerifyingContextFactory(ssl.CertificateOptions):
    """``OpenSSL.SSL.Context`` factory which does full certificate-chain and
    hostname verfication.
    """
    isClient = True

    def __init__(self, url, **kwargs):
        """Create a client-side verifying SSL Context factory.

        To pass acceptable certificates for a server which does
        client-authentication checks: initialise with a ``caCerts=[]`` keyword
        argument, which should be a list of ``OpenSSL.crypto.X509`` instances
        (one for each peer certificate to add to the store), and set
        ``SSLVerifyingContextFactory.isClient=False``.

        :param str url: The URL being requested by an
            :api:`twisted.web.client.Agent`.
        :param bool isClient: True if we're being used in a client
            implementation; False if we're a server.
        """
        self.hostname = self.getHostnameFromURL(url)

        # ``verify`` here refers to server-side verification of certificates
        # presented by a client:
        self.verify = False if self.isClient else True
        super(SSLVerifyingContextFactory, self).__init__(verify=self.verify,
                                                         fixBrokenPeers=True,
                                                         **kwargs)

    def getContext(self, hostname=None, port=None):
        """Retrieve a configured ``OpenSSL.SSL.Context``.

        Any certificates in the ``caCerts`` list given during initialisation
        are added to the ``Context``'s certificate store.

        The **hostname** and **port** arguments seem unused, but they are
        required due to some Twisted and pyOpenSSL internals. See
        :api:`twisted.web.client.Agent._wrapContextFactory`.

        :rtype: ``OpenSSL.SSL.Context``
        :returns: An SSL Context which verifies certificates.
        """
        ctx = super(SSLVerifyingContextFactory, self).getContext()
        store = ctx.get_cert_store()
        verifyOptions = OpenSSL.SSL.VERIFY_PEER
        ctx.set_verify(verifyOptions, self.verifyHostname)
        return ctx

    def getHostnameFromURL(self, url):
        """Parse the hostname from the originally requested URL.

        :param str url: The URL being requested by an
            :api:`twisted.web.client.Agent`.
        :rtype: str
        :returns: The full hostname (including any subdomains).
        """
        hostname = urllib.splithost(urllib.splittype(url)[1])[0]
        logging.debug("Parsed hostname %r for cert CN matching." % hostname)
        return hostname

    def verifyHostname(self, connection, x509, errnum, depth, okay):
        """Callback method for additional SSL certificate validation.

        If the certificate is signed by a valid CA, and the chain is valid,
        verify that the level 0 certificate has a subject common name which is
        valid for the hostname of the originally requested URL.

        :param connection: An ``OpenSSL.SSL.Connection``.
        :param x509: An ``OpenSSL.crypto.X509`` object.
        :param errnum: A pyOpenSSL error number. See that project's docs.
        :param depth: The depth which the current certificate is at in the
            certificate chain.
        :param bool okay: True if all the pyOpenSSL default checks on the
            certificate passed. False otherwise.
        """
        commonName = x509.get_subject().commonName
        logging.debug("Received cert at level %d: '%s'" % (depth, commonName))

        # We only want to verify that the hostname matches for the level 0
        # certificate:
        if okay and (depth == 0):
            cn = commonName.replace('*', '.*')
            hostnamesMatch = re.search(cn, self.hostname)
            if not hostnamesMatch:
                logging.warn("Invalid certificate subject CN for '%s': '%s'"
                             % (self.hostname, commonName))
                return False
            logging.debug("Valid certificate subject CN for '%s': '%s'"
                          % (self.hostname, commonName))
        return True
