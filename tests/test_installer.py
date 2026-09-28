"""Unit tests for the optional system installer."""
import os
import stat
import tempfile

from _load import Checker, installer, me


IDENTITY = "person@example.test"
CERT = "-----BEGIN CERTIFICATE-----\nY2VydA==\n-----END CERTIFICATE-----\n"
CA = "-----BEGIN CERTIFICATE-----\nY2E=\n-----END CERTIFICATE-----\n"
KEY = "-----BEGIN PRIVATE KEY-----\na2V5\n-----END PRIVATE KEY-----\n"


def run():
    check = Checker()
    with tempfile.TemporaryDirectory(prefix="mist-installer-") as directory:
        wifi_path = os.path.join(directory, "wifi.nmconnection")
        wired_path = os.path.join(directory, "wired.nmconnection")
        _write(wifi_path, me.wifi_profile(IDENTITY, CERT, KEY, CA))
        _write(wired_path, me.wired_profile(IDENTITY, CERT, KEY, CA))

        wifi = installer.read_profile(wifi_path, "wifi")
        wired = installer.read_profile(wired_path, "802-3-ethernet")
        check("installer reads the generated profiles",
              wifi["identity"] == IDENTITY and wifi["ssid"] == "eduroam"
              and wired["identity"] == IDENTITY)
        check("installer recovers all embedded credential material",
              wifi["ca"] == CA.encode() and wifi["client"] == CERT.encode()
              and wifi["key"] == KEY.encode())
        check("installer requires matching credentials",
              installer.matching_material(wifi, wired))

        cert_dir = installer.certificate_dir(directory, wifi)
        paths = installer.write_certificates(cert_dir, wifi)
        check("certificate directory is private",
              stat.S_IMODE(os.stat(cert_dir).st_mode) == 0o700)
        check("credential files are mode 0600",
              all(stat.S_IMODE(os.stat(path).st_mode) == 0o600
                  for path in paths.values()))
        check("credential directory is stable for the same credentials",
              cert_dir == installer.certificate_dir(directory, wired))

        commands = installer.command_plan(
            wifi, wired, paths, "wifi-test", "wired-test",
            "wlan0", "eth0")
        rendered = [" ".join(command) for command in commands]
        check("installer creates fresh wifi and ethernet connections",
              commands[0][:6] == ["nmcli", "connection", "add", "type", "wifi", "ifname"]
              and "con-name wifi-test" in rendered[0]
              and "type ethernet" in rendered[2]
              and "con-name wired-test" in rendered[2])
        check("installer binds the requested interfaces",
              "ifname wlan0" in rendered[0] and "ifname eth0" in rendered[2])
        check("nmcli profiles reference persistent PEM paths",
              all(paths[name] in rendered[1] and paths[name] in rendered[3]
                  for name in ("ca", "client", "key")))
        check("both profiles use EAP-TLS without a password prompt",
              "802-1x.eap tls" in rendered[1]
              and "802-1x.private-key-password-flags 4" in rendered[1]
              and "802-1x.eap tls" in rendered[3]
              and "802-1x.private-key-password-flags 4" in rendered[3])
        check("wired profile gets the intended autoconnect priority",
              "connection.autoconnect-priority 10" in rendered[3])

        bad_path = os.path.join(directory, "bad.nmconnection")
        _write(bad_path, me.wifi_profile(IDENTITY, CERT, KEY, CA).replace(
            "ca-cert=data:;base64,", "ca-cert=/tmp/"))
        check("installer rejects non-embedded input credentials",
              _raises(lambda: installer.read_profile(bad_path, "wifi")))

    return check.failures


def _write(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def _raises(fn):
    try:
        fn()
    except installer.InstallError:
        return True
    return False


if __name__ == "__main__":
    import sys
    print("installer tests")
    sys.exit(1 if run() else 0)
