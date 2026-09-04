"""End-to-end tests: the real enrollment path against a mock SCEP CA, and the
CLI against a mock Mist enrollment endpoint."""
import base64
import configparser
import glob
import json
import os
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import mockca
from _load import SCRIPT, Checker, me

IDENTITY = "laurence.bowes@plymouth.ac.uk"
QUIET = lambda *a, **k: None


def run():
    check = Checker()
    if not shutil.which("openssl"):
        print("  openssl not found -- skipping end-to-end tests")
        return []

    workdir = tempfile.mkdtemp(prefix="mist-e2e-")
    _server, scep_url = mockca.start()

    def openssl(cmd):
        return subprocess.run(cmd, shell=True, capture_output=True, cwd=workdir)

    def enroll(device_id):
        ssldir = tempfile.mkdtemp(prefix="mist-e2e-ssl-")
        try:
            return me.enroll_scep(me.OpenSSL(ssldir), scep_url, IDENTITY,
                                  "chal", device_id, log=QUIET)
        finally:
            shutil.rmtree(ssldir, ignore_errors=True)

    # --- happy path --------------------------------------------------------
    mockca.reset()
    key_pem, cert_pem = enroll("dev-1")
    check("only a PKCSReq was sent", mockca.STATE["seen_types"] == ["19"])

    with open(os.path.join(workdir, "ca.pem"), "w") as handle:
        handle.write(mockca.CA_PEM)
    with open(os.path.join(workdir, "issued.pem"), "w") as handle:
        handle.write(cert_pem)
    with open(os.path.join(workdir, "key.pem"), "w") as handle:
        handle.write(key_pem)

    result = openssl("openssl verify -CAfile ca.pem issued.pem")
    check("issued certificate chains to the CA", result.returncode == 0,
          result.stderr.decode()[:200])
    text = openssl("openssl x509 -in issued.pem -noout -subject -ext subjectAltName"
                   ).stdout.decode()
    check("issued certificate carries the identity", IDENTITY in text, text)
    check("issued certificate carries the device SAN", "dev-1" in text, text)
    check("private key matches the issued certificate",
          openssl("openssl x509 -in issued.pem -noout -pubkey").stdout
          == openssl("openssl pkey -in key.pem -pubout").stdout)

    # --- GetCACert delivered as PKCS#7 ------------------------------------
    mockca.reset()
    mockca.STATE["ca_format"] = "p7"
    _k2, cert2 = enroll("dev-2")
    check("works when GetCACert returns a PKCS#7 bundle",
          "BEGIN CERTIFICATE" in cert2)

    # --- PENDING is reported, not retried ---------------------------------
    mockca.reset()
    mockca.STATE["pending_left"] = 99
    check("a PENDING reply is reported with a likely cause",
          _raises_message(lambda: enroll("dev-3"), "fresh URL"))

    # --- CA rejects the request -------------------------------------------
    mockca.reset()
    mockca.STATE["mode"] = "fail"
    check("a FAILURE reply is reported with its failInfo",
          _raises_message(lambda: enroll("dev-5"), "badRequest"))

    # --- nonce mismatch is caught -----------------------------------------
    mockca.reset()
    mockca.STATE["mode"] = "badnonce"
    check("a mismatched recipientNonce is rejected",
          _raises_message(lambda: enroll("dev-6"), "nonce"))

    # --- CA replies in other ciphers --------------------------------------
    for reply_cipher in ("des", "des3", "aes-128-cbc", "aes-256-cbc"):
        mockca.reset()
        mockca.STATE["reply_cipher"] = reply_cipher
        _k, cert = enroll("dev-8")
        check("decrypts a reply encrypted with %s" % reply_cipher,
              "BEGIN CERTIFICATE" in cert)

    # --- profile content ---------------------------------------------------
    check.failures.extend(_check_profiles(cert_pem, key_pem, mockca.CA_PEM))

    # --- the CLI, end to end ----------------------------------------------
    check.failures.extend(_check_cli(workdir, scep_url))

    shutil.rmtree(workdir, ignore_errors=True)
    return check.failures


def _check_profiles(cert_pem, key_pem, ca_pem):
    check = Checker()
    wifi = me.wifi_profile(IDENTITY, cert_pem, key_pem, ca_pem)
    wired = me.wired_profile(IDENTITY, cert_pem, key_pem, ca_pem)

    for label, text, conn_type in (("wifi", wifi, "wifi"),
                                   ("wired", wired, "802-3-ethernet")):
        parser = configparser.ConfigParser()
        parser.optionxform = str
        parser.read_string(text)
        check("%s profile has the right 802.1X fields" % label,
              parser["connection"]["type"] == conn_type
              and parser["802-1x"]["eap"] == "tls"
              and parser["802-1x"]["identity"] == IDENTITY
              and parser["802-1x"]["private-key-password-flags"] == "4"
              and parser["802-1x"]["system-ca-certs"] == "false"
              and parser["ipv4"]["method"] == "auto"
              and parser["ipv6"]["method"] == "auto")
        check("%s profile embeds our certificate" % label,
              _blob(parser["802-1x"]["client-cert"]) == cert_pem)
        check("%s profile embeds our private key" % label,
              _blob(parser["802-1x"]["private-key"]) == key_pem)
        check("%s profile embeds the CA certificate" % label,
              _blob(parser["802-1x"]["ca-cert"]) == ca_pem)

    parser = configparser.ConfigParser()
    parser.optionxform = str
    parser.read_string(wired)
    check("wired profile has an empty [802-3-ethernet] section",
          dict(parser["802-3-ethernet"]) == {})
    check("wired profile sets id and autoconnect-priority",
          parser["connection"]["id"] == "plymouth_wired"
          and parser["connection"]["autoconnect-priority"] == "10")
    check("wired profile has no wifi sections",
          not parser.has_section("wifi") and not parser.has_section("wifi-security"))
    for label, text in (("wifi", wifi), ("wired", wired)):
        check("%s profile carries the secret-key warning" % label,
              "KEEP SECRET" in text and IDENTITY in text.splitlines()[1])
        check("%s profile warning is a keyfile comment, before any section" % label,
              all(line.startswith("#") for line in text.splitlines()[:3])
              and text.splitlines()[3].startswith("["))
    return check.failures


def _check_cli(workdir, scep_url):
    check = Checker()
    # A self-signed cert for the mock endpoint, valid for 127.0.0.1. We point
    # SSL_CERT_FILE at it rather than disabling verification, so the CLI runs
    # with certificate checking fully on.
    subprocess.run("openssl req -x509 -newkey rsa:2048 -keyout s.key -out s.crt "
                   "-days 5 -nodes -subj '/CN=localhost' "
                   "-addext 'subjectAltName=IP:127.0.0.1,DNS:localhost'",
                   shell=True, capture_output=True, cwd=workdir)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert "device_id" in body
            payload = json.dumps({"nac": {
                "identity": IDENTITY,
                "scep_url": scep_url,
                "scep_enrollment_challenge": "chal-abc",
                "nac_server_cert": mockca.CA_PEM,
            }}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(os.path.join(workdir, "s.crt"),
                            os.path.join(workdir, "s.key"))
    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    enroll_url = "https://127.0.0.1:%d/api/v1/mobile/enroll/token" % \
        server.server_address[1]

    def cli(*args, **kwargs):
        """Run the CLI. The URL is fed on stdin -- it is prompted for, never
        passed as an argument."""
        env = dict(os.environ)
        if kwargs.pop("trust", True):
            env["SSL_CERT_FILE"] = os.path.join(workdir, "s.crt")
        return subprocess.run([sys.executable, SCRIPT] + list(args),
                              input=kwargs.pop("stdin", ""),
                              capture_output=True, text=True, env=env,
                              cwd=kwargs.pop("cwd", workdir))

    out = os.path.join(workdir, "out")
    os.makedirs(out, exist_ok=True)
    mockca.reset()
    result = cli(stdin=enroll_url + "\n", cwd=out)
    check("CLI succeeds", result.returncode == 0, result.stderr[:400])
    names = sorted(os.path.basename(p) for p in glob.glob(out + "/*"))
    check("CLI writes exactly the two profiles",
          names == ["plymouth_eduroam.nmconnection",
                    "plymouth_wired.nmconnection"], str(names))
    check("both profiles are mode 0600",
          all(stat.S_IMODE(os.stat(p).st_mode) == 0o600
              for p in glob.glob(out + "/*")))
    check("CLI leaves no temporary directory behind",
          not glob.glob("/tmp/mist-enroll-*"))

    parser = configparser.ConfigParser()
    parser.optionxform = str
    parser.read_string(open(out + "/plymouth_eduroam.nmconnection").read())
    with open(os.path.join(workdir, "cli-cert.pem"), "w") as handle:
        handle.write(_blob(parser["802-1x"]["client-cert"]))
    verify = subprocess.run("openssl verify -CAfile ca.pem cli-cert.pem",
                            shell=True, capture_output=True, cwd=workdir)
    check("the certificate in the profile chains to the CA",
          verify.returncode == 0, verify.stderr.decode()[:200])
    check("the profile identity is the one Mist returned",
          parser["802-1x"]["identity"] == IDENTITY)
    check("CLI warns that the files contain a private key",
          "private key" in result.stdout.lower() and "secret" in result.stdout.lower(),
          result.stdout[-400:])
    check("CLI prints the install commands rather than installing",
          "sudo install" in result.stdout
          and "nmcli connection reload" in result.stdout
          and me.PROFILE_DIR in result.stdout, result.stdout[-400:])
    check("CLI names the files it wrote in the install commands",
          "plymouth_eduroam.nmconnection" in result.stdout
          and "plymouth_wired.nmconnection" in result.stdout)
    check("CLI tells you to shred the leftovers", "shred -u" in result.stdout)
    check("CLI did not touch the system profile directory",
          not os.path.exists(os.path.join(me.PROFILE_DIR,
                                          "plymouth_wired.nmconnection")))

    out2 = os.path.join(workdir, "out2")
    os.makedirs(out2, exist_ok=True)
    mockca.reset()
    result = cli(stdin=enroll_url.replace("https://", "marvisclient://") + "\n",
                 cwd=out2)
    check("marvisclient:// URLs are accepted", result.returncode == 0,
          result.stderr[:300])
    check("marvisclient:// run writes both profiles",
          len(glob.glob(out2 + "/*")) == 2)

    result = cli(stdin="http://insecure.example/x\n")
    check("a plain-http enrollment URL is refused",
          result.returncode == 1 and "https" in result.stderr, result.stderr[:200])
    check("a rejected URL explains where to get a real one",
          "eduroam.plymouth.ac.uk" in result.stderr
          and "Install network profile" in result.stderr, result.stderr[:300])

    result = cli("--help")
    check("--help explains where to get the URL",
          "eduroam.plymouth.ac.uk" in result.stdout and "Chromium" in result.stdout)

    out3 = os.path.join(workdir, "out3")
    os.makedirs(out3, exist_ok=True)
    mockca.reset()
    result = cli(enroll_url, cwd=out3)
    check("the URL can be passed as an argument instead of typed",
          result.returncode == 0, result.stderr[:300])
    check("the argument path writes both profiles",
          len(glob.glob(out3 + "/*")) == 2)

    result = cli("--nonsense")
    check("an unknown flag is refused",
          result.returncode == 2 and "usage:" in result.stderr, result.stderr[:200])
    result = cli(enroll_url, "extra")
    check("more than one argument is refused",
          result.returncode == 2 and "usage:" in result.stderr, result.stderr[:200])

    result = cli(stdin="")
    check("EOF at the prompt aborts cleanly (no traceback)",
          result.returncode == 130 and "Traceback" not in result.stderr,
          result.stderr[:200])

    ro = os.path.join(workdir, "readonly")
    os.makedirs(ro, exist_ok=True)
    os.chmod(ro, 0o500)
    mockca.reset()
    try:
        result = cli(stdin=enroll_url + "\n", cwd=ro)
        check("an unwritable directory gives a clear error, not a traceback",
              result.returncode == 1 and "Traceback" not in result.stderr
              and "writable directory" in result.stderr, result.stderr[-300:])
    finally:
        os.chmod(ro, 0o700)

    result = cli(stdin="   \n")
    check("a whitespace-only response is treated as empty",
          result.returncode == 2 and "No enrollment URL" in result.stderr)

    check("the prompt explains where to get the URL before asking",
          "eduroam.plymouth.ac.uk" in result.stdout
          and "Enter the Mist enrollment URL" in result.stdout, result.stdout[:200])

    result = cli(stdin=enroll_url + "\n", trust=False)
    check("TLS verification is on (untrusted cert is refused)",
          result.returncode == 1
          and "certificate" in (result.stderr + result.stdout).lower(),
          result.stderr[:200])
    return check.failures


def _blob(value):
    return base64.b64decode(value.split(",", 1)[1]).decode()


def _raises_message(fn, needle):
    try:
        fn()
    except me.ScepError as exc:
        return needle.lower() in str(exc).lower()
    except Exception:
        return False
    return False


if __name__ == "__main__":
    print("end-to-end tests")
    sys.exit(1 if run() else 0)
