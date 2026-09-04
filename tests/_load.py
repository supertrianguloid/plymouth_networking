"""Import ../mist-enroll as a module (it has no .py extension by design)."""
import importlib.machinery
import importlib.util
import os

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "mist-enroll")


def load():
    loader = importlib.machinery.SourceFileLoader("mist_enroll", SCRIPT)
    spec = importlib.util.spec_from_loader("mist_enroll", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


me = load()


class Checker:
    def __init__(self):
        self.failures = []

    def __call__(self, name, condition, extra=""):
        ok = bool(condition)
        print("  %-52s %s %s" % (name, "ok" if ok else "FAIL", "" if ok else extra))
        if not ok:
            self.failures.append(name)
        return ok
