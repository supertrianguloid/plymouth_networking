"""Unit tests for the DER/ASN.1 layer and the openssl wrapper.

There is no hand-rolled crypto left to test -- openssl does all of it -- so
these cover the ASN.1 structures we still assemble ourselves, plus the helper
logic around openssl invocation.
"""
import os
import shutil
import subprocess
import tempfile

from _load import Checker, me


def run():
    check = Checker()

    # --- DER encoding ------------------------------------------------------
    check("DER INTEGER",
          me.der_int(0) == b"\x02\x01\x00"
          and me.der_int(127) == b"\x02\x01\x7f"
          and me.der_int(128) == b"\x02\x02\x00\x80"
          and me.der_int(256) == b"\x02\x02\x01\x00")
    check("DER OID",
          me.der_oid("1.2.840.113549.1.1.1") == bytes.fromhex("06092a864886f70d010101"))
    check("DER OID with large arcs",
          me.read_oid(me.parse_one(me.der_oid(me.OID_SCEP_TRANS_ID))[0])
          == me.OID_SCEP_TRANS_ID)
    check("short and long form lengths",
          me.enc_len(127) == b"\x7f" and me.enc_len(128) == b"\x81\x80"
          and me.enc_len(300) == b"\x82\x01\x2c")
    check("long-form lengths round-trip",
          me.parse_one(me.der_octets(b"x" * 5000))[0].body == b"x" * 5000)

    # --- DER parsing -------------------------------------------------------
    check("truncated DER is rejected",
          _raises(lambda: me.parse_one(b"\x30\x82\x01")))
    check("indefinite-length DER is rejected",
          _raises(lambda: me.parse_one(b"\x30\x80\x00\x00")))
    nested = me.der_seq(me.der_int(1), me.der_octets(b"ab"), me.der_printable("x"))
    kids = me.parse_one(nested)[0].children()
    check("nested parsing", len(kids) == 3 and me.read_int(kids[0]) == 1
          and kids[1].body == b"ab" and kids[2].body == b"x")

    # --- openssl config escaping ------------------------------------------
    check("config escaping neutralises $ and backslashes",
          me.conf_escape(r"a$b\c") == r"a\$b\\c")
    check("config escaping leaves ordinary values alone",
          me.conf_escape("laurence.bowes@plymouth.ac.uk")
          == "laurence.bowes@plymouth.ac.uk")

    # --- PEM splitting -----------------------------------------------------
    one = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"
    check("split_pem finds a single block", me.split_pem(one) == [one])
    check("split_pem finds several blocks",
          len(me.split_pem("subject=x\n" + one + "subject=y\n" + one)) == 2)
    check("split_pem ignores non-certificate text", me.split_pem("nothing here") == [])

    # --- capability negotiation -------------------------------------------
    check("negotiate prefers SHA-512",
          me.negotiate({"POSTPKIOperation", "SHA-512", "AES"}) == "sha512")
    check("negotiate handles the live Mist capability set",
          me.negotiate({"POSTPKIOperation", "Renewal", "SCEPStandard", "SHA-512"})
          == "sha512")
    check("SCEPStandard alone implies AES and SHA-256",
          me.negotiate({"SCEPStandard"}) == "sha256")
    check("negotiate refuses an empty capability list",
          _message(lambda: me.negotiate(set()), "nothing"))
    check("negotiate refuses a server with neither AES nor SCEPStandard",
          _raises(lambda: me.negotiate({"SHA-256", "DES3"}), me.ScepError))

    # --- malformed replies are reported, not crashed on --------------------
    for name, blob in [
        ("empty", b""),
        ("truncated", b"\x30\x82\x05"),
        ("not signedData", me.der_seq(me.der_oid("1.2.3.4"))),
        ("signedData without signerInfos",
         me.der_seq(me.der_oid(me.OID_PKCS7_SIGNED),
                    me.der_tagged(0, me.der_seq(me.der_int(1))))),
        ("random bytes", bytes(range(64))),
    ]:
        check("a %s reply raises ScepError, not a parser error" % name,
              _raises_only(lambda b=blob: me.read_signed_attributes(b), me.ScepError))

    # --- recipient selection -----------------------------------------------
    check("one certificate is used as the recipient",
          me.pick_recipient(["cert"]) == "cert")
    check("no certificates is an error",
          _message(lambda: me.pick_recipient([]), "got 0"))
    check("more than one certificate fails loudly rather than guessing",
          _message(lambda: me.pick_recipient(["a", "b"]), "got 2"))

    # --- pkiStatus handling ------------------------------------------------
    check("SUCCESS passes", me.check_status({me.OID_SCEP_PKI_STATUS: b"0"}) is None)
    check("FAILURE reports its failInfo",
          _message(lambda: me.check_status({me.OID_SCEP_PKI_STATUS: b"2",
                                            me.OID_SCEP_FAIL_INFO: b"2"}),
                   "badRequest"))
    check("PENDING explains the likely cause",
          _message(lambda: me.check_status({me.OID_SCEP_PKI_STATUS: b"3"}),
                   "fresh URL"))
    check("a missing pkiStatus is an error",
          _raises(lambda: me.check_status({}), me.ScepError))

    # --- scratch directory -------------------------------------------------
    workdir = me.make_workdir()
    try:
        check("scratch dir is private (0700)",
              oct(os.stat(workdir).st_mode & 0o777) == "0o700")
        check("scratch dir prefers tmpfs when available",
              workdir.startswith("/dev/shm/") or not os.path.isdir("/dev/shm"),
              workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if not shutil.which("openssl"):
        print("  openssl not found -- skipping openssl-backed checks")
        return check.failures

    workdir = tempfile.mkdtemp(prefix="mist-units-")
    try:
        openssl = me.OpenSSL(workdir)
        check("openssl major version detected", openssl.major >= 1)

        check("a failing openssl call raises with its stderr",
              _message(lambda: openssl.run(["x509", "-in", "/nonexistent"]),
                       "openssl x509 failed"))

        key = openssl.path("k.pem")
        openssl.generate_key(key)
        check("generated key is mode 0600",
              oct(os.stat(key).st_mode & 0o777) == "0o600")
        check("generated key passes openssl's full consistency check",
              b"BEGIN PRIVATE KEY" in open(key, "rb").read()
              and openssl.run(["pkey", "-in", key, "-noout", "-check"],
                              binary=False).strip().endswith("is valid"))
        text = openssl.run(["pkey", "-in", key, "-noout", "-text"], binary=False)
        check("generated key is 2048-bit with two primes",
              "Private-Key: (2048 bit, 2 primes)" in text, text[:120])
        check("generated key uses the standard public exponent",
              "65537" in text)
        second = openssl.path("k2.pem")
        openssl.generate_key(second)
        check("successive keys differ",
              openssl.public_key(key) != openssl.public_key(second))

        config = openssl.path("req.cnf")
        me.write_req_config(config, "laurence.bowes@plymouth.ac.uk",
                            "chal$with\\specials", "device-uuid-1")
        csr = openssl.path("req.der")
        openssl.make_csr(key, config, csr, "sha512")
        text = openssl.run(["req", "-inform", "DER", "-in", csr, "-noout", "-text"],
                           binary=False)
        check("CSR carries the identity", "laurence.bowes@plymouth.ac.uk" in text)
        check("CSR carries the device SAN", "device-uuid-1" in text)
        check("CSR carries the challengePassword", "challengePassword" in text)
        check("config escaping survives round-trip into the CSR",
              "chal$with\\specials" in text, text)
        check("CSR signature verifies under openssl",
              openssl.run(["req", "-inform", "DER", "-in", csr, "-noout", "-verify"],
                          binary=False) is not None)

        signer = openssl.path("signer.der")
        openssl.make_self_signed(key, config, signer, "sha512")
        pem = openssl.der_to_pem(_read(signer))
        check("self-signed certificate parses", "BEGIN CERTIFICATE" in pem)
        check("issuer_and_serial is well-formed DER",
              me.parse_one(me.issuer_and_serial(_read(signer)))[0].tag == 0x30)
        check("issuer_and_serial picks up the serial we set",
              me.read_int(me.parse_one(me.issuer_and_serial(_read(signer)))[0]
                          .children()[1]) == 1)
        check("cert public key matches the private key",
              openssl.cert_public_key(pem) == openssl.public_key(key))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    return check.failures


def _read(path):
    with open(path, "rb") as handle:
        return handle.read()


def _raises_only(fn, exc):
    """True if fn raises exactly `exc` and nothing else leaks through."""
    try:
        fn()
    except exc:
        return True
    except BaseException:
        return False
    return False


def _raises(fn, exc=Exception):
    try:
        fn()
    except exc:
        return True
    except Exception:
        return False
    return False


def _message(fn, needle):
    try:
        fn()
    except Exception as exc:
        return needle.lower() in str(exc).lower()
    return False


if __name__ == "__main__":
    import sys
    print("unit tests")
    sys.exit(1 if run() else 0)
