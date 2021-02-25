#!/usr/bin/env python

"""Test cases for "signer.py". """

import sys
import os
import unittest
import tempfile
import shutil

import securesystemslib.formats
import securesystemslib.keys as KEYS
from securesystemslib.exceptions import FormatError, UnsupportedAlgorithmError
from securesystemslib.gpg.exceptions import CommandError, KeyExpirationError
from securesystemslib.gpg.constants import HAVE_GPG
from securesystemslib.gpg.functions import (
    export_pubkey,
    verify_signature as verify_sig
)

# TODO: Remove case handling when fully dropping support for versions < 3.6
IS_PY_VERSION_SUPPORTED = sys.version_info >= (3, 6)

# Use setUpModule to tell unittest runner to skip this test module gracefully.
def setUpModule():
    if not IS_PY_VERSION_SUPPORTED:
        raise unittest.SkipTest("requires Python 3.6 or higher")

# Since setUpModule is called after imports we need to import conditionally.
if IS_PY_VERSION_SUPPORTED:
    from securesystemslib.signer import Signature, SSlibSigner, GPGSigner


class TestSSlibSigner(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rsakey_dict = KEYS.generate_rsa_key()
        cls.ed25519key_dict = KEYS.generate_ed25519_key()
        cls.ecdsakey_dict = KEYS.generate_ecdsa_key()
        cls.DATA_STR = "SOME DATA REQUIRING AUTHENTICITY."
        cls.DATA = securesystemslib.formats.encode_canonical(
                cls.DATA_STR).encode("utf-8")


    def test_sslib_sign(self):
        dicts = [self.rsakey_dict, self.ecdsakey_dict, self.ed25519key_dict]
        for scheme_dict in dicts:
            # Test generation of signatures.
            sslib_signer = SSlibSigner(scheme_dict)
            sig_obj = sslib_signer.sign(self.DATA)

            # Verify signature
            verified = KEYS.verify_signature(scheme_dict, sig_obj.to_dict(),
                    self.DATA)
            self.assertTrue(verified, "Incorrect signature.")

            # Removing private key from "scheme_dict".
            private = scheme_dict["keyval"]["private"]
            scheme_dict["keyval"]["private"] = ""
            sslib_signer.key_dict = scheme_dict

            with self.assertRaises((ValueError, FormatError)):
                sslib_signer.sign(self.DATA)

            scheme_dict["keyval"]["private"] = private

            # Test for invalid signature scheme.
            valid_scheme = scheme_dict["scheme"]
            scheme_dict["scheme"] = "invalid_scheme"
            sslib_signer = SSlibSigner(scheme_dict)

            with self.assertRaises((UnsupportedAlgorithmError, FormatError)):
                sslib_signer.sign(self.DATA)

            scheme_dict["scheme"] = valid_scheme


    def test_signature_from_to_dict(self):
        signature_dict = {
            "sig": "30460221009342e4566528fcecf6a7a5d53ebacdb1df151e242f55f8775883469cb01dbc6602210086b426cc826709acfa2c3f9214610cb0a832db94bbd266fd7c5939a48064a851",
            "keyid": "11fa391a0ed7a447cbfeb4b2667e286fc248f64d5e6d0eeed2e5e23f97f9f714"
        }
        sig_obj = Signature.from_dict(signature_dict)

        self.assertDictEqual(signature_dict, sig_obj.to_dict())



@unittest.skipIf(not HAVE_GPG, "gpg not found")
class TestGPGRSA(unittest.TestCase):
    """Test RSA gpg signature creation and verification."""

    @classmethod
    def setUpClass(self):
        self.default_keyid = "8465A1E2E0FB2B40ADB2478E18FB3F537E0C8A17"
        self.signing_subkey_keyid = "C5A0ABE6EC19D0D65F85E2C39BE9DF5131D924E9"

        # Create directory to run the tests without having everything blow up.
        self.working_dir = os.getcwd()
        self.test_data = b'test_data'
        self.wrong_data = b'something malicious'

        # Find demo files.
        gpg_keyring_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "gpg_keyrings", "rsa")

        self.test_dir = os.path.realpath(tempfile.mkdtemp())
        self.gnupg_home = os.path.join(self.test_dir, "rsa")
        shutil.copytree(gpg_keyring_path, self.gnupg_home)
        os.chdir(self.test_dir)


    @classmethod
    def tearDownClass(self):
        """Change back to initial working dir and remove temp test directory."""

        os.chdir(self.working_dir)
        shutil.rmtree(self.test_dir)


    def test_gpg_sign_and_verify_object_with_default_key(self):
        """Create a signature using the default key on the keyring. """

        signer = GPGSigner(homedir=self.gnupg_home)
        signature = signer.sign(self.test_data)

        signature_dict = signature.to_dict()
        key_data = export_pubkey(self.default_keyid, self.gnupg_home)

        self.assertTrue(verify_sig(signature_dict, key_data, self.test_data))
        self.assertFalse(verify_sig(signature_dict, key_data, self.wrong_data))


    def test_gpg_sign_and_verify_object(self):
        """Create a signature using a specific key on the keyring. """

        signer = GPGSigner(self.signing_subkey_keyid, self.gnupg_home)
        signature = signer.sign(self.test_data)

        signature_dict = signature.to_dict()
        key_data = export_pubkey(self.signing_subkey_keyid, self.gnupg_home)

        self.assertTrue(verify_sig(signature_dict, key_data, self.test_data))
        self.assertFalse(verify_sig(signature_dict, key_data, self.wrong_data))


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
