import hashlib
import mimetypes
import os

SUSPICIOUS_EXTENSIONS = {
".exe",
".scr",
".bat",
".cmd",
".vbs",
".js",
".ps1",
".msi"
}

def calculate_hashes(filepath):

md5 = hashlib.md5()
sha1 = hashlib.sha1()
sha256 = hashlib.sha256()

with open(filepath, "rb") as file:

    while True:

        chunk = file.read(8192)

        if not chunk:
            break

        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)

return {
    "md5": md5.hexdigest(),
    "sha1": sha1.hexdigest(),
    "sha256": sha256.hexdigest()
}

def analyze_file(filepath):

filename = os.path.basename(filepath)

extension = os.path.splitext(
    filename
)[1].lower()

size = os.path.getsize(filepath)

mime_type, _ = mimetypes.guess_type(
    filepath
)

findings = []

score = 0

if extension in SUSPICIOUS_EXTENSIONS:

    findings.append(
        "Potentially executable or script "
        f"extension detected: {extension}"
    )

    score += 40

if filename.lower().endswith(
    (
        ".pdf.exe",
        ".jpg.exe",
        ".png.exe",
        ".doc.exe",
        ".docx.exe"
    )
):

    findings.append(
        "Possible double-extension disguise."
    )

    score += 30

if size == 0:

    findings.append(
        "File is empty."
    )

    score += 10

if size > 5 * 1024 * 1024:

    findings.append(
        "File is larger than 5 MB."
    )

    score += 5

hashes = calculate_hashes(filepath)

if not findings:

    findings.append(
        "No basic suspicious indicators detected."
    )

return {
    "filename": filename,
    "extension": extension or "None",
    "size": size,
    "mime_type": mime_type or "Unknown",
    "hashes": hashes,
    "score": min(score, 100),
    "findings": findings
}
