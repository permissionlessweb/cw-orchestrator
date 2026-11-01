"""Drive the real cw-orch-kms challenge page in headless Chromium.

The QR decode result is injected at the exact spot zxing hands text to the page
(the onText callback of cwOrchScan.start), after clicking the page's own Scan
button. The throwaway test key signs like Zigner direct-sign: secp256k1 over
sha256(sign doc), low-s. Prints PAGE-ADVANCED-TO <label> when the tab moved on.
"""
import base64, hashlib, os, re, sys, time
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_string_canonize
from playwright.sync_api import sync_playwright

url, mode = sys.argv[1], sys.argv[2]
sk = SigningKey.from_string(bytes.fromhex(os.environ["REPLAY_THROWAWAY_KEY_HEX"]), curve=SECP256k1)
pk = sk.get_verifying_key().to_string("compressed")

def sign(doc):
    return sk.sign_digest(hashlib.sha256(doc).digest(), sigencode=sigencode_string_canonize)

INJECT = """() => {
  window.__frames = [];
  cwOrchScan.start = function (video, status, onText) { window.__onText = onText; status.textContent = "camera (replay)"; return { reset: function () {} }; };
  cwOrchScan.stop = function () {};
}"""

with sync_playwright() as p:
    b = p.chromium.launch(executable_path=os.environ.get("CW_ORCH_KMS_REPLAY_CHROME"), headless=True)
    page = b.new_page()
    reloads = []
    page.on("framenavigated", lambda f: reloads.append(f.url) if f == page.main_frame else None)
    page.goto(url)
    html = page.content()
    m = re.search(r"(cw-orch-granter:v2 [^<]*?) is the granter", html)
    binding = m.group(1)
    doc = ("cw-orch-granter:v1\n" + binding).encode()
    exp = int(re.search(r"expires=(\d+)", binding).group(1))
    print("challenge ttl from now:", exp - int(time.time()))
    page.wait_for_function("() => typeof cwOrchScan !== 'undefined'")
    page.wait_for_timeout(1500)  # let the 1s /state poll run at least once mid-scan
    page.evaluate(INJECT)
    page.click("#scan")
    sig = sign(doc)
    def fire(text):
        page.evaluate("t => window.__onText(t)", text)
    if mode == "bare":
        fire(sig.hex())
    elif mode == "envelope194":
        fire((pk + sig).hex())
    elif mode == "pframes":
        b64 = base64.b64encode(pk + sig).decode()
        half = len(b64) // 2
        fire("P1/2/x/" + b64[:half]); page.wait_for_timeout(300); fire("P2/2/x/" + b64[half:])
    elif mode == "bare-nokey-then-envelope":
        fire(sig.hex())
        page.wait_for_function("() => /not accepted/.test(document.body.innerText)", timeout=10000)
        print("refusal shown:", page.inner_text("#scan-status") if page.query_selector("#scan-status") else "")
        page.evaluate(INJECT); page.click("#scan")
        fire((pk + sig).hex())
    # The page must advance by itself: the tab reloads on the next instance and shows authorize.
    page.wait_for_function("() => { var h = document.getElementById('run-head'); return h && /authorize/.test(h.textContent); }", timeout=20000)
    print("run-head:", page.inner_text("#run-head"))
    print("navigations:", len(reloads))
    print("PAGE-ADVANCED-TO authorize")
    b.close()
