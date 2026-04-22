# StegCheck - User Guide for GitHub

## Overview

StegCheck is a Python command-line steganalysis tool that scans files for common indicators of hidden embedded data.

It helps identify suspicious files such as images, audio, video, or renamed files that may contain appended archives or payloads.

---

## Features

* Detects real file type from headers (magic bytes)
* Calculates entropy score
* Detects embedded ZIP / RAR / 7z / PDF / EXE signatures
* Detects trailing data after JPEG EOF marker
* Produces LOW / MEDIUM / HIGH suspicion score
* Works on images, audio, video, documents, binaries
* Cross-platform (Windows / Linux / macOS)

---

## Installation

### Requirements

* Python 3.8+

Check Python:

```bash
python --version
```

### Clone Repository

```bash
git clone https://github.com/yourusername/stegcheck.git
cd stegcheck
```

Or download ZIP and extract.

---

## Usage

Run basic scan:

```bash
python stegcheck.py sample.jpg
```

Scan audio:

```bash
python stegcheck.py song.mp3
```

Scan video:

```bash
python stegcheck.py movie.mp4
```

Scan suspicious file:

```bash
python stegcheck.py suspect.bin
```

---

## Example Output

```text
File: photo.jpg
Size: 812344 bytes
Detected Type: JPEG image
Entropy: 7.91/8.00
Embedded Signatures:
  - ZIP archive at offset 452188
Risk Score: 80
Verdict: HIGH suspiciousness
```

---

## Suspicion Levels

| Score | Meaning |
| ----- | ------- |
| 0-24  | LOW     |
| 25-59 | MEDIUM  |
| 60+   | HIGH    |

---

## Supported Detection Methods

* Magic byte mismatch
* Embedded archive signatures
* Appended payload detection
* High entropy detection
* Unknown header anomaly

---

## Example Use Cases

* Check if image contains hidden archive
* Detect disguised executable files
  n- Inspect suspicious audio/video files
* Classroom CEH labs
* Basic DFIR triage

---

## Disclaimer

This tool provides indicators only. It does not guarantee that a file is malicious or contains steganography. Use additional forensic analysis for confirmation.

---

## License

MIT License

---

## Author

Your Name Here
