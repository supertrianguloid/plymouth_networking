"""A mock SCEP CA, backed by a real openssl-generated CA.

The request side is validated with the openssl binary before anything is
issued, so the client's outgoing messages are checked by an independent
implementation rather than by our own parser.
"""
import os
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from _load import me

WORK = tempfile.mkdtemp(prefix="mist-mockca-")

STATE = {
    "mode": "success",     # or "fail", "badnonce"
    "pending_left": 0,
    "seen_types": [],
    "ca_format": "der",    # or "p7"
    # exactly what the live Mist NAC server returns
    "caps": b"POSTPKIOperation\nRenewal\nSCEPStandard\nSHA-512\n",
    "reply_cipher": "des",
    "csr": None,
}


def sh(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, cwd=WORK)
    if result.returncode:
        raise RuntimeError(cmd + "\n" + result.stderr.decode())
    return result.stdout


sh("openssl req -x509 -newkey rsa:2048 -keyout cakey.pem -out ca.pem -days 30 "
   "-nodes -subj '/CN=Mock SCEP CA' "
   "-addext 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign' "
   "-addext 'basicConstraints=critical,CA:TRUE' 2>/dev/null")

CA_DER = sh("openssl x509 -in ca.pem -outform DER")
CA_PEM = open(os.path.join(WORK, "ca.pem")).read()


CA_KEY_PATH = os.path.join(WORK, "cakey.pem")
CA_CERT_PATH = os.path.join(WORK, "ca.pem")
CA_CERT_DER_PATH = os.path.join(WORK, "ca.der")
sh("openssl x509 -in ca.pem -outform DER -out ca.der")
OPENSSL = me.OpenSSL(WORK)


# The live Mist CA replies with single DES-CBC despite advertising
# SCEPStandard, so that is what the mock does by default.
def _issue(csr_der, requester_pem, cipher=None):
    with open(os.path.join(WORK, "req.der"), "wb") as handle:
        handle.write(csr_der)
    sh("openssl req -inform DER -in req.der -noout -verify")  # independent check
    sh("openssl x509 -req -inform DER -in req.der -CA ca.pem -CAkey cakey.pem "
       "-set_serial 0x%s -days 30 -out issued.pem -copy_extensions copy 2>/dev/null"
       % os.urandom(8).hex())
    sh("openssl crl2pkcs7 -nocrl -certfile issued.pem -certfile ca.pem "
       "-outform DER -out deg.der")
    with open(os.path.join(WORK, "deg.der"), "rb") as handle:
        degenerate = handle.read()
    requester_path = os.path.join(WORK, "requester.pem")
    with open(requester_path, "w") as handle:
        handle.write(requester_pem)
    args = ["cms", "-encrypt", "-binary", "-outform", "DER",
            "-" + (cipher or STATE["reply_cipher"]), requester_path]
    return OPENSSL.run(args, stdin=degenerate,
                       legacy=(cipher or STATE["reply_cipher"]) == "des")


def _reply(payload, status, trans_id, recipient_nonce, fail=None):
    attrs = [
        me.attribute(me.OID_SCEP_MESSAGE_TYPE, me.der_printable("3")),
        me.attribute(me.OID_SCEP_PKI_STATUS, me.der_printable(status)),
        me.attribute(me.OID_SCEP_TRANS_ID, me.der_printable(trans_id)),
        me.attribute(me.OID_SCEP_RECIPIENT_NONCE, me.der_octets(recipient_nonce)),
        me.attribute(me.OID_SCEP_SENDER_NONCE, me.der_octets(os.urandom(16))),
    ]
    if fail is not None:
        attrs.append(me.attribute(me.OID_SCEP_FAIL_INFO, me.der_printable(fail)))
    with open(CA_CERT_DER_PATH, "rb") as handle:
        ca_der = handle.read()
    return me.build_pki_message(OPENSSL, CA_KEY_PATH, ca_der,
                                payload or b"", attrs, "sha256")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, data, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        operation = parse_qs(urlparse(self.path).query).get("operation", [""])[0]
        if operation == "GetCACaps":
            self._send(STATE["caps"], "text/plain")
        elif operation == "GetCACert":
            if STATE["ca_format"] == "der":
                self._send(CA_DER, "application/x-x509-ca-cert")
            else:
                self._send(sh("openssl crl2pkcs7 -nocrl -certfile ca.pem -outform DER"),
                           "application/x-x509-ca-ra-cert")
        else:
            self.send_response(400)
            self.end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        with open(os.path.join(WORK, "msg.der"), "wb") as handle:
            handle.write(body)
        # Independent checks: openssl must accept the client's signed message
        # and be able to open the envelope addressed to the CA.
        sh("openssl cms -verify -inform DER -in msg.der -noverify "
           "-out inner.der -outform DER")
        inner = sh("openssl cms -decrypt -inform DER -in inner.der "
                   "-inkey cakey.pem -recip ca.pem")

        attrs = me.read_signed_attributes(body)
        message_type = attrs[me.OID_SCEP_MESSAGE_TYPE].decode()
        trans_id = attrs[me.OID_SCEP_TRANS_ID].decode()
        nonce = attrs[me.OID_SCEP_SENDER_NONCE]
        STATE["seen_types"].append(message_type)
        signer_pem = sh("openssl pkcs7 -inform DER -in msg.der -print_certs")
        requester_pem = me.split_pem(signer_pem.decode())[0]

        if message_type == "19":
            STATE["csr"] = inner
        if STATE["mode"] == "fail":
            return self._send(_reply(None, "2", trans_id, nonce, fail="2"),
                              "application/x-pki-message")
        if STATE["pending_left"] > 0:
            STATE["pending_left"] -= 1
            return self._send(_reply(None, "3", trans_id, nonce),
                              "application/x-pki-message")
        echoed = os.urandom(16) if STATE["mode"] == "badnonce" else nonce
        payload = _issue(STATE["csr"], requester_pem)
        self._send(_reply(payload, "0", trans_id, echoed),
                   "application/x-pki-message")


def start():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, "http://127.0.0.1:%d/scep" % server.server_address[1]


def reset():
    STATE.update(mode="success", pending_left=0, seen_types=[], ca_format="der",
                 caps=b"POSTPKIOperation\nRenewal\nSCEPStandard\nSHA-512\n",
                 reply_cipher="des")
