# app.py  -- MVP secure wipe + cert (Windows-friendly)
import os
import sys
import json
import uuid
import base64
import hashlib
import tempfile
from datetime import datetime, timezone
from fpdf import FPDF
from fpdf.enums import XPos, YPos 
import qrcode
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

# -------- utilities --------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024*1024)
            if not chunk: break
            h.update(chunk)
    return h.hexdigest()

def canonical_json_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')

# -------- wipe logic (safe file overwrite) --------
def wipe_file(path, passes=1, block_size=1024*1024, progress_callback=None):
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        for p in range(passes):
            f.seek(0)
            written = 0
            while written < size:
                to_write = min(block_size, size - written)
                f.write(b'\x00' * to_write)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
                written += to_write
                if progress_callback:
                    progress_callback(min(1.0, ((p*size)+written)/(passes*size)))
    try:
        os.sync()
    except Exception:
        # os.sync may not exist on Windows; ignore
        pass

# -------- certificate and signing --------
def make_unsigned_certificate(path, method, result, extra_log=""):
    cert = {
        "certificate_id": str(uuid.uuid4()),
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "wiper_version": "mvp-windows-0.1",
        "file_path": str(Path(path).resolve()),
        "file_size_bytes": os.path.getsize(path),
        "method": method,
        "result": result,
        "extra_log": extra_log
    }
    return cert

def sign_certificate(unsigned_cert, privkey_path):
    with open(privkey_path, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    data = canonical_json_bytes(unsigned_cert)
    sig = priv.sign(data, ec.ECDSA(hashes.SHA256()))
    sig_b64 = base64.b64encode(sig).decode('ascii')
    signed = dict(unsigned_cert)
    signed["signature"] = sig_b64
    signed["signature_algorithm"] = "ECDSA-P256-SHA256"
    return signed

def verify_signed_certificate(signed_cert, pubkey_path):
    if "signature" not in signed_cert:
        return False, "no signature"
    sig_b64 = signed_cert["signature"]
    sig = base64.b64decode(sig_b64)
    unsigned = {k:v for k,v in signed_cert.items() if k not in ("signature","signature_algorithm")}
    data = canonical_json_bytes(unsigned)
    with open(pubkey_path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    try:
        pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True, "signature valid"
    except InvalidSignature:
        return False, "invalid signature"

# -------- PDF generation --------
def generate_pdf_certificate(signed_cert, json_path, pdf_path):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_margins(left=10, top=10, right=10)
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 10, "Secure Wipe Certificate (MVP)", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.ln(6)
    pdf.set_font("helvetica", "", 11)

    usable_width = pdf.w - pdf.l_margin - pdf.r_margin

    for k in ("certificate_id", "issued_at", "wiper_version", "file_path", "file_size_bytes", "method", "result"):
        if k in signed_cert:
            val = str(signed_cert[k])
            wrapped_lines = [val[i:i+100] for i in range(0, len(val), 100)]
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(usable_width, 8, f"{k}:")
            for line in wrapped_lines:
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(usable_width, 8, line)

    pdf.ln(4)
    qr_data = f"https://n6si.github.io/secure-wipe-certs/{os.path.basename(json_path)}"
    qr_img = qrcode.make(qr_data)
    tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    tmpname = tmp.name
    qr_img.save(tmpname)
    pdf.image(tmpname, x=10, y=pdf.get_y(), w=40)
    pdf.ln(45)
    pdf.set_font("helvetica", "", 9)
    pdf.multi_cell(usable_width, 6, "Signature algorithm: " + signed_cert.get("signature_algorithm", ""))
    pdf.output(pdf_path)

    try:
        os.unlink(tmpname)
    except:
        pass


# -------- runner --------
def run_wipe_and_issue(path, privkey="keys/priv.pem", passes=1):
    log = []
    log.append(f"starting wipe: {path}")
    before_hash = sha256_file(path)
    log.append("before_sha256:" + before_hash)
    wipe_file(path, passes=passes, progress_callback=None)
    after_hash = sha256_file(path)
    log.append("after_sha256:" + after_hash)
    unsigned = make_unsigned_certificate(path, f"overwrite-zero-passes-{passes}", "SUCCESS", extra_log=";".join(log))
    signed = sign_certificate(unsigned, privkey)
    out_json = f"{unsigned['certificate_id']}.json"
    out_pdf  = f"{unsigned['certificate_id']}.pdf"
    with open(out_json, "w") as f:
        json.dump(signed, f, indent=2)
    generate_pdf_certificate(signed, out_json, out_pdf)
    return out_json, out_pdf, signed

# -------- CLI entry --------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="MVP secure wipe + cert (Windows)")
    parser.add_argument("--create-testfile", action="store_true", help="create testfile.bin (50MB)")
    parser.add_argument("--wipe", help="path to file to wipe (demo: testfile.bin)")
    parser.add_argument("--passes", type=int, default=1, help="overwrite passes")
    parser.add_argument("--signer", default="keys/priv.pem", help="private key path")
    parser.add_argument("--verify", help="verify signed json file")
    parser.add_argument("--pub", default="keys/pub.pem", help="public key path for verify")
    args = parser.parse_args()

    if args.create_testfile:
        p = "testfile.bin"
        size_mb = 50
        print("Creating", p)
        with open(p, "wb") as f:
            for _ in range(size_mb):
                f.write(os.urandom(1024*1024))
        print("done:", p, os.path.getsize(p))
        sys.exit(0)

    if args.wipe:
        print("Wiping", args.wipe)
        j, pdf, signed = run_wipe_and_issue(args.wipe, privkey=args.signer, passes=args.passes)
        print("JSON saved:", j)
        print("PDF saved:", pdf)
        sys.exit(0)

    if args.verify:
        print("Verifying", args.verify)
        with open(args.verify, "r") as f:
            data = json.load(f)
        ok, msg = verify_signed_certificate(data, args.pub)
        print("VERIFY:", ok, msg)
        sys.exit(0)

    parser.print_help()
