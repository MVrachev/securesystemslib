"""Signer interface and example interface implementations.

The goal of this module is to provide a signing interface supporting multiple
signing implementations and a couple of example implementations.

"""

import abc
from typing import Dict, Optional
import securesystemslib.keys as sslib_keys
import securesystemslib.gpg.functions as gpg

class Signature:
    """A container class containing information about a signature.

    Contains a signature and the keyid uniquely identifying the key used
    to generate the signature.

    Provides utility methods to easily create an object from a dictionary
    and return the dictionary representation of the object.

    Attributes:
        keyid: HEX string used as a unique identifier of the key.
        signature: HEX string representing the signature.

    """
    def __init__(self, keyid: str, sig: str):
        self.keyid = keyid
        self.signature = sig


    @classmethod
    def from_dict(cls, signature_dict: Dict) -> "Signature":
        """Creates a Signature object from its JSON/dict representation.

        Arguments:
            signature_dict:
                A dict containing a valid keyid and a signature.
                Note that the fields in it should be named "keyid" and "sig"
                respectively.

        Raises:
            KeyError: If any of the "keyid" and "sig" fields are missing from
                the signature_dict.

        Returns:
            A "Signature" instance.
        """

        return cls(signature_dict["keyid"], signature_dict["sig"])


    def to_dict(self) -> Dict:
        """Returns the JSON-serializable dictionary representation of self."""

        return {
            "keyid": self.keyid,
            "sig": self.signature
        }



class GPGSignature(Signature):
    """A container class containing information about a gpg signature.

    Besides the signature, it also contains other meta information
    needed to uniquely identify the key used to generate the signature.

    Attributes:
        keyid: HEX string used as a unique identifier of the key.
        signature: HEX string representing the signature.
        other_headers: HEX representation of additional GPG headers.
        info: An optional dict containing information about the GPG key
            used to generate the signature and the signed data.
    """
    def __init__(self, keyid: str, signature: str, other_headers: str,
            info: dict = None):
        super().__init__(keyid, signature)
        self.other_headers = other_headers
        self.info = info


    @classmethod
    def from_dict(cls, signature_dict: Dict) -> "Signature":
        """Creates a GPGSignature object from its JSON/dict representation.

        Arguments:
            signature_dict:
                A dict containing valid "keyid", "signature" and "other_fields"
                fields.

        Raises:
            KeyError: If any of the "keyid", "sig" or "other_headers" fields are
                missing from the signature_dict.

        Returns:
            A "GPGSignature" instance.
        """

        return cls(signature_dict["keyid"], signature_dict["sig"],
                signature_dict["other_headers"], signature_dict.get("info"))


    def to_dict(self) -> Dict:
        """Returns the JSON-serializable dictionary representation of self."""

        res = {"keyid": self.keyid, "signature": self.signature,
            "other_headers": self.other_headers}

        if self.info:
            res["info"] = self.info

        return res



class Signer:
    """Signer interface created to support multiple signing implementations."""

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def sign(self, payload: bytes) -> "Signature":
        """Signs a given payload by the key assigned to the Signer instance.

        Arguments:
            payload: The bytes to be signed.

        Returns:
            Returns a "Signature" class instance.
        """
        raise NotImplementedError # pragma: no cover



class SSlibSigner(Signer):
    """A securesystemslib signer implementation.

    Provides a sign method to generate a cryptographic signature with a
    securesystemslib-style rsa, ed25519 or ecdsa private key on the instance.
    The signature scheme is determined by the key and must be one of:

    - rsa(ssa-pss|pkcs1v15)-(md5|sha1|sha224|sha256|sha384|sha512) (12 schemes)
    - ed25519
    - ecdsa-sha2-nistp256

    See "securesystemslib.interface" for functions to generate and load keys.

    Attributes:
        key_dict:
            A securesystemslib-style key dictionary, which includes a keyid,
            key type, signature scheme, and the public and private key values,
            e.g.::

                {
                    "keytype": "rsa",
                    "scheme": "rsassa-pss-sha256",
                    "keyid": "f30a0870d026980100c0573bd557394f8c1bbd6...",
                    "keyval": {
                        "public": "-----BEGIN RSA PUBLIC KEY----- ...",
                        "private": "-----BEGIN RSA PRIVATE KEY----- ..."
                    }
                }

            The public and private keys are strings in PEM format.
    """
    def __init__(self, key_dict: Dict):
        self.key_dict = key_dict


    def sign(self, payload: bytes) -> "Signature":
        """Signs a given payload by the key assigned to the SSlibSigner instance.

        Arguments:
            payload: The bytes to be signed.

        Raises:
            securesystemslib.exceptions.FormatError: Key argument is malformed.
            securesystemslib.exceptions.CryptoError, \
                securesystemslib.exceptions.UnsupportedAlgorithmError:
                Signing errors.

        Returns:
            Returns a "Signature" class instance.
        """

        sig_dict = sslib_keys.create_signature(self.key_dict, payload)
        return Signature(**sig_dict)



class GPGSigner(Signer):
    """A securesystemslib gpg implementation of the "Signer" interface.

    Provides a sign method to generate a cryptographic signature with gpg, using
    an RSA, DSA or EdDSA private key identified by the keyid on the instance.

    Attributes:
        keyid: (optional)
              The keyid of the gpg signing keyid. If not passed the default
              key in the keyring is used.

        homedir: (optional)
              Path to the gpg keyring. If not passed the default keyring is used.

    """
    def __init__(
            self, keyid: Optional[str] = None,
            homedir: Optional[str] = None):
        self.keyid = keyid
        self.homedir = homedir


    def sign(self, payload: bytes) -> "GPGSignature":
        """Signs a given payload by the key assigned to the GPGSigner instance.

        Calls the gpg command line utility to sign the passed content with the
        key identified by the passed keyid from the gpg keyring at the passed
        homedir.

        The executed base command is defined in
        securesystemslib.gpg.constants.GPG_SIGN_COMMAND.

        Arguments:
            payload: The bytes to be signed.

        Raises:
            securesystemslib.exceptions.FormatError:
                If the keyid was passed and does not match
                securesystemslib.formats.KEYID_SCHEMA.

            ValueError: the gpg command failed to create a valid signature.
            OSError: the gpg command is not present or non-executable.
            securesystemslib.exceptions.UnsupportedLibraryError: thehe gpg
                command is not available, or the cryptography library is
                not installed.
            securesystemslib.gpg.exceptions.CommandError: the gpg command
                returned a non-zero exit code.
            securesystemslib.gpg.exceptions.KeyNotFoundError: the used gpg
                version is not fully supported and no public key can be found
                for short keyid.

        Returns:
            Returns a "GPGSignature" class instance.
        """

        sig_dict = gpg.create_signature(payload, self.keyid, self.homedir)
        return GPGSignature(**sig_dict)
