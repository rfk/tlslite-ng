# Author: Stanislav Zidek
# See the LICENSE file for legal information regarding use of this file.

"""Abstract class for ECDSA."""

from .cryptomath import *
from . import tlshashlib as hashlib
from ..errors import MaskTooLongError, MessageTooLongError, EncodingError, \
    InvalidSignature


class ECDSAKey(object):
    """This is an abstract base class for ECDSA keys.

    Particular implementations of ECDSA keys, such as
    :py:class:`~.python_ecdsakey.Python_ECDSAKey`
    ... more coming
    inherit from this.

    To create or parse an ECDSA key, don't use one of these classes
    directly.  Instead, use the factory functions in
    :py:class:`~tlslite.utils.keyfactory`.
    """

    def __init__(self, public_key, private_key):
        """Create a new ECDSA key.

        If public_key or private_key are passed in, the new key
        will be initialized.

        :param public_key: ECDSA public key.

        :param private_key: ECDSA private key.
        """
        raise NotImplementedError()

    def __len__(self):
        """Return the length of this key in bits.

        :rtype: int
        """
        raise NotImplementedError()

    def hasPrivateKey(self):
        """Return whether or not this key has a private component.

        :rtype: bool
        """
        raise NotImplementedError()

    def _sign(self, data):
        raise NotImplementedError()

    def _hashAndSign(self, data, hAlg):
        raise NotImplementedError()

    def hashAndSign(self, bytes, rsaScheme=None, hAlg='sha1', sLen=None):
        """Hash and sign the passed-in bytes.

        This requires the key to have a private component. It performs
        a signature on the passed-in data with selected hash algorithm.

        :type bytes: str or bytearray
        :param bytes: The value which will be hashed and signed.

        :type rsaScheme: str
        :param rsaScheme: Ignored

        :type hAlg: str
        :param hAlg: The hash algorithm that will be used

        :type sLen: int
        :param sLen: Ignored

        :rtype: bytearray
        :returns: A PKCS1 or PSS signature on the passed-in data.
        """
        rsaScheme = rsaScheme.lower()
        hAlg = hAlg.lower()
        hashBytes = secureHash(bytearray(bytes), hAlg)
        return self.sign(hashBytes, padding=rsaScheme, hashAlg=hAlg,
                         saltLen=sLen)

    def hashAndVerify(self, sigBytes, bytes, rsaScheme='PKCS1', hAlg='sha1',
                      sLen=0):
        """Hash and verify the passed-in bytes with the signature.

        This verifies a PKCS1 or PSS signature on the passed-in data
        with selected hash algorithm.

        :type sigBytes: bytearray
        :param sigBytes: A PKCS1 or PSS signature.

        :type bytes: str or bytearray
        :param bytes: The value which will be hashed and verified.

        :type rsaScheme: str
        :param rsaScheme: The type of ECDSA scheme that will be applied,
                          "PKCS1" for ECDSASSA-PKCS#1 v1.5 signature and "PSS"
                          for ECDSASSA-PSS with MGF1 signature method

        :type hAlg: str
        :param hAlg: The hash algorithm that will be used

        :type sLen: int
        :param sLen: The length of intended salt value, applicable only
                     for ECDSASSA-PSS signatures

        :rtype: bool
        :returns: Whether the signature matches the passed-in data.
        """
        rsaScheme = rsaScheme.lower()
        hAlg = hAlg.lower()

        hashBytes = secureHash(bytearray(bytes), hAlg)
        return self.verify(sigBytes, hashBytes, rsaScheme, hAlg, sLen)

    def sign(self, bytes, padding='pkcs1', hashAlg=None, saltLen=None):
        """Sign the passed-in bytes.

        This requires the key to have a private component.  It performs
        a PKCS1 signature on the passed-in data.

        :type bytes: bytearray
        :param bytes: The value which will be signed.

        :type padding: str
        :param padding: name of the rsa padding mode to use, supported:
            "pkcs1" for ECDSASSA-PKCS1_1_5 and "pss" for ECDSASSA-PSS.

        :type hashAlg: str
        :param hashAlg: name of hash to be encoded using the PKCS#1 prefix
            for "pkcs1" padding or the hash used for MGF1 in "pss". Parameter
            is mandatory for "pss" padding.

        :type saltLen: int
        :param saltLen: length of salt used for the PSS padding. Default
            is the length of the hash output used.

        :rtype: bytearray
        :returns: A PKCS1 signature on the passed-in data.
        """
        padding = padding.lower()
        if padding == 'pkcs1':
            if hashAlg is not None:
                bytes = self.addPKCS1Prefix(bytes, hashAlg)
            sigBytes = self._raw_pkcs1_sign(bytes)
        elif padding == "pss":
            sigBytes = self.ECDSASSA_PSS_sign(bytes, hashAlg, saltLen)
        else:
            raise UnknownECDSAType("Unknown ECDSA algorithm type")
        return sigBytes

    def verify(self, sigBytes, bytes, padding='pkcs1', hashAlg=None,
               saltLen=None):
        """Verify the passed-in bytes with the signature.

        This verifies a PKCS1 signature on the passed-in data.

        :type sigBytes: bytearray
        :param sigBytes: A PKCS1 signature.

        :type bytes: bytearray
        :param bytes: The value which will be verified.

        :rtype: bool
        :returns: Whether the signature matches the passed-in data.
        """
        if padding == "pkcs1" and hashAlg == 'sha1':
            # Try it with/without the embedded NULL
            prefixedHashBytes1 = self.addPKCS1SHA1Prefix(bytes, False)
            prefixedHashBytes2 = self.addPKCS1SHA1Prefix(bytes, True)
            result1 = self._raw_pkcs1_verify(sigBytes, prefixedHashBytes1)
            result2 = self._raw_pkcs1_verify(sigBytes, prefixedHashBytes2)
            return (result1 or result2)
        elif padding == 'pkcs1':
            if hashAlg is not None:
                bytes = self.addPKCS1Prefix(bytes, hashAlg)
            res = self._raw_pkcs1_verify(sigBytes, bytes)
            return res
        elif padding == "pss":
            try:
                res = self.ECDSASSA_PSS_verify(bytes, sigBytes, hashAlg, saltLen)
            except InvalidSignature:
                res = False
            return res
        else:
            raise UnknownECDSAType("Unknown ECDSA algorithm type")

    def acceptsPassword(self):
        """Return True if the write() method accepts a password for use
        in encrypting the private key.

        :rtype: bool
        """
        raise NotImplementedError()

    def write(self, password=None):
        """Return a string containing the key.

        :rtype: str
        :returns: A string describing the key, in whichever format (PEM)
            is native to the implementation.
        """
        raise NotImplementedError()

    @staticmethod
    def generate(bits):
        """Generate a new key with the specified bit length.

        :rtype: ~tlslite.utils.ECDSAKey.ECDSAKey
        """
        raise NotImplementedError()
