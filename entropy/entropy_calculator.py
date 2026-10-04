# ============================================================
# ENTROPY - Entropy Calculator
# entropy\entropy_calculator.py
#
# WHAT THIS DOES:
# Calculates Shannon entropy of files.
# Entropy measures randomness in data.
# Normal files = low entropy
# Encrypted files = high entropy (close to 8.0)
#
# SHANNON ENTROPY FORMULA:
# H = -sum( p(x) * log2(p(x)) )
# Where p(x) = probability of each byte value (0-255)
# ============================================================

import os
import sys
import math
import time
import json
import hashlib
import logging
from datetime import datetime
from collections import defaultdict

# Add parent folder to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

log = logging.getLogger("EntropyCalc")


# ============================================================
# CORE ENTROPY CALCULATION
# ============================================================

def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of a byte sequence.

    WHAT THIS MEASURES:
    -------------------
    How random/unpredictable the data is.

    SCALE:
    ------
    0.0 = All bytes are the same (e.g., all zeros)
    4.0 = Normal English text
    6.0 = Compressed data (ZIP, DOCX)
    7.5 = JPEG images, MP4 videos
    8.0 = Perfectly random (encrypted data)

    HOW IT WORKS:
    -------------
    1. Count how many times each byte value (0-255) appears
    2. Calculate probability of each byte value
    3. Apply Shannon formula: H = -sum(p * log2(p))
    4. Result is between 0.0 and 8.0

    Args:
        data: Raw bytes from the file

    Returns:
        float: Entropy score between 0.0 and 8.0
    """

    if not data:
        return 0.0

    # Step 1: Count frequency of each byte value
    # There are 256 possible byte values (0x00 to 0xFF)
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    # Step 2: Calculate entropy
    total_bytes = len(data)
    entropy = 0.0

    for count in byte_counts:
        if count == 0:
            continue  # log2(0) is undefined, skip

        # Probability of this byte value appearing
        probability = count / total_bytes

        # Shannon formula contribution from this byte value
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def calculate_file_entropy(file_path: str,
                           sample_size: int = None) -> dict:
    """
    Calculate entropy of a file.

    Reads the file and calculates its entropy.
    Also calculates entropy of different sections
    (beginning, middle, end) to detect partial encryption.

    Args:
        file_path:   Path to the file
        sample_size: How many bytes to read (None = entire file)

    Returns:
        Dictionary with detailed entropy information
    """

    if sample_size is None:
        sample_size = config.SAMPLE_SIZE_BYTES

    result = {
        'file_path'       : file_path,
        'timestamp'       : datetime.now().isoformat(),
        'entropy_overall' : 0.0,
        'entropy_start'   : 0.0,   # first 1/3 of sample
        'entropy_middle'  : 0.0,   # middle 1/3 of sample
        'entropy_end'     : 0.0,   # last 1/3 of sample
        'file_size'       : 0,
        'bytes_read'      : 0,
        'file_extension'  : '',
        'file_hash'       : '',
        'is_readable'     : False,
        'error'           : None,
    }

    # Get file extension
    _, ext = os.path.splitext(file_path)
    result['file_extension'] = ext.lower()

    # Try to read the file
    try:
        # Get file size
        result['file_size'] = os.path.getsize(file_path)

        # Read the file bytes
        with open(file_path, 'rb') as f:
            data = f.read(sample_size)

        result['bytes_read'] = len(data)
        result['is_readable'] = True

        if len(data) == 0:
            result['error'] = 'File is empty'
            return result

        # Calculate overall entropy
        result['entropy_overall'] = calculate_entropy(data)

        # Calculate section entropies
        # This helps detect partial encryption
        # (some ransomware only encrypts part of the file)
        third = len(data) // 3

        if third > 0:
            result['entropy_start']  = calculate_entropy(data[:third])
            result['entropy_middle'] = calculate_entropy(data[third:2*third])
            result['entropy_end']    = calculate_entropy(data[2*third:])

        # Calculate file hash (SHA-256)
        # Used as fingerprint for blockchain
        sha256 = hashlib.sha256()
        sha256.update(data)
        result['file_hash'] = sha256.hexdigest()

    except PermissionError:
        result['error'] = 'Permission denied'
    except FileNotFoundError:
        result['error'] = 'File not found'
    except Exception as e:
        result['error'] = str(e)

    return result


# ============================================================
# ENTROPY ANALYZER
# Goes beyond raw entropy calculation.
# Compares entropy to baseline, detects anomalies.
# ============================================================

class EntropyAnalyzer:
    """
    Analyzes file entropy and determines if it is suspicious.

    This class:
    1. Calculates current entropy of a file
    2. Compares to historical entropy (if file was seen before)
    3. Compares to normal range for that file type
    4. Returns an analysis with threat indicators
    """

    def __init__(self):
        # Store previous entropy readings for each file
        # Key: file_path, Value: list of entropy scores over time
        self.entropy_history = defaultdict(list)

        # Maximum history entries per file
        self.max_history = 10

    def analyze(self, file_path: str) -> dict:
        """
        Full entropy analysis of a file.

        Returns a comprehensive analysis dictionary including:
        - Current entropy
        - Historical comparison
        - Threat indicators
        - Recommendation
        """

        # Step 1: Calculate current entropy
        entropy_data = calculate_file_entropy(file_path)

        if not entropy_data['is_readable']:
            return self._build_result(
                entropy_data,
                score        = 0.0,
                is_suspicious= False,
                reason       = f"Cannot read file: {entropy_data['error']}"
            )

        current_entropy = entropy_data['entropy_overall']
        ext             = entropy_data['file_extension']

        # Step 2: Get historical entropy for this file
        history      = self.entropy_history[file_path]
        prev_entropy = history[-1] if history else None
        entropy_delta = 0.0

        if prev_entropy is not None:
            entropy_delta = current_entropy - prev_entropy

        # Step 3: Update history
        history.append(current_entropy)
        if len(history) > self.max_history:
            history.pop(0)

        # Step 4: Check against known normal ranges
        normal_range    = config.NORMAL_ENTROPY_RANGES.get(ext, (3.0, 7.5))
        normal_min      = normal_range[0]
        normal_max      = normal_range[1]
        # A tiny amount above the empirical range is measurement noise for
        # compressed formats. Require a meaningful margin before scoring it.
        above_normal    = current_entropy > (normal_max + 0.5)

        # Step 5: Calculate threat indicators
        indicators = []
        threat_score = 0.0

        # Indicator 1: Absolute entropy threshold. High entropy is normal
        # for many legitimate formats (images, video, archives), so it is
        # only an indicator by itself for unknown formats. Known formats are
        # evaluated against their type-specific range below.
        if current_entropy >= config.ENTROPY_THRESHOLD and (
            ext not in config.NORMAL_ENTROPY_RANGES
        ):
            indicators.append(
                f"High entropy: {current_entropy:.2f} "
                f"(threshold: {config.ENTROPY_THRESHOLD})"
            )
            threat_score += 40.0

        # Indicator 2: Entropy above normal for file type
        if above_normal and ext in config.NORMAL_ENTROPY_RANGES:
            indicators.append(
                f"Above normal for {ext}: "
                f"{current_entropy:.2f} "
                f"(normal: {normal_min:.1f}-{normal_max:.1f})"
            )
            threat_score += 40.0

        # Indicator 3: Large entropy jump from previous reading
        if abs(entropy_delta) >= config.ENTROPY_DELTA_THRESHOLD:
            indicators.append(
                f"Large entropy change: "
                f"{entropy_delta:+.2f} "
                f"(from {prev_entropy:.2f} to {current_entropy:.2f})"
            )
            threat_score += 30.0

        # Indicator 4: Section entropy anomaly
        # If end of file has much higher entropy than start,
        # could indicate partial encryption in progress
        if entropy_data['entropy_start'] > 0:
            section_delta = (entropy_data['entropy_end'] -
                           entropy_data['entropy_start'])
            if section_delta > 2.0:
                indicators.append(
                    f"Section entropy anomaly: "
                    f"start={entropy_data['entropy_start']:.2f} "
                    f"end={entropy_data['entropy_end']:.2f}"
                )
                threat_score += 15.0

        # Step 6: Determine if suspicious
        is_suspicious = threat_score >= 40.0

        # Build reason string
        if indicators:
            reason = " | ".join(indicators)
        else:
            reason = (f"Normal entropy {current_entropy:.2f} "
                     f"for {ext} files")

        return self._build_result(
            entropy_data,
            score         = min(threat_score, 100.0),
            is_suspicious = is_suspicious,
            reason        = reason,
            entropy_delta = entropy_delta,
            prev_entropy  = prev_entropy,
            normal_range  = normal_range,
            indicators    = indicators
        )

    def _build_result(self, entropy_data, score,
                      is_suspicious, reason,
                      entropy_delta=0.0, prev_entropy=None,
                      normal_range=(0.0, 8.0), indicators=None):
        """Build a standardized result dictionary."""

        return {
            # ── File Info ──────────────────────────────────
            'file_path'       : entropy_data['file_path'],
            'file_extension'  : entropy_data['file_extension'],
            'file_size'       : entropy_data['file_size'],
            'file_hash'       : entropy_data.get('file_hash', ''),

            # ── Entropy Values ─────────────────────────────
            'entropy_overall' : entropy_data.get('entropy_overall', 0.0),
            'entropy_start'   : entropy_data.get('entropy_start', 0.0),
            'entropy_middle'  : entropy_data.get('entropy_middle', 0.0),
            'entropy_end'     : entropy_data.get('entropy_end', 0.0),
            'entropy_delta'   : round(entropy_delta, 4),
            'prev_entropy'    : prev_entropy,

            # ── Normal Range for this file type ───────────
            'normal_range_min': normal_range[0],
            'normal_range_max': normal_range[1],

            # ── Analysis Result ────────────────────────────
            'threat_score'    : round(score, 2),
            'is_suspicious'   : is_suspicious,
            'reason'          : reason,
            'indicators'      : indicators or [],

            # ── Metadata ──────────────────────────────────
            'timestamp'       : entropy_data.get('timestamp', ''),
            'is_readable'     : entropy_data.get('is_readable', False),
            'error'           : entropy_data.get('error', None),
        }

    def transfer_history(self, source_path: str, dest_path: str) -> None:
        """Keep entropy history across ransomware-style renames."""
        if not source_path or not dest_path or source_path == dest_path:
            return
        history = self.entropy_history.get(source_path)
        if history:
            self.entropy_history[dest_path] = list(history)

    def snapshot_directory(self, root: str) -> int:
        """Prime entropy history for every file under *root*.

        The startup baseline. Without this, the FIRST event on a
        pre-existing file has no delta (empty history), so a rename
        that encrypts an old file scores only its raw-entropy points
        (alert, not quarantine). Priming makes the first-event delta
        real — this is exactly what the benchmark's "baseline mode"
        models, so production and the benchmark agree.

        Read-only: mirrors BackupManager.snapshot_directory.
        """
        count = 0
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                path = os.path.join(dirpath, name)
                if os.path.isfile(path):
                    self.analyze(path)
                    count += 1
        return count

    def get_history(self, file_path: str) -> list:
        """Get entropy history for a specific file."""
        return list(self.entropy_history.get(file_path, []))

    def clear_history(self, file_path: str = None):
        """Clear entropy history."""
        if file_path:
            self.entropy_history.pop(file_path, None)
        else:
            self.entropy_history.clear()


# ============================================================
# ENTROPY VISUALIZER
# Displays entropy as a visual bar in the terminal.
# Makes it easy to understand the entropy value at a glance.
# ============================================================

def visualize_entropy(entropy: float,
                      label: str = "",
                      width: int = 40) -> str:
    """
    Create a text-based entropy bar visualization.

    Example output:
    [========================================] 8.00 ENCRYPTED
    [==========================              ] 5.20 NORMAL
    [================                        ] 3.10 LOW

    Args:
        entropy: Entropy value (0.0 to 8.0)
        label:   Optional label to show
        width:   Width of the bar in characters

    Returns:
        Formatted string for display
    """

    # Calculate fill amount
    fill = int((entropy / 8.0) * width)
    fill = max(0, min(fill, width))

    bar = '=' * fill + ' ' * (width - fill)

    # Choose status label based on entropy
    if entropy >= 7.5:
        status = "ENCRYPTED/COMPRESSED"
    elif entropy >= 6.0:
        status = "COMPRESSED"
    elif entropy >= 4.0:
        status = "NORMAL"
    elif entropy >= 2.0:
        status = "LOW"
    else:
        status = "VERY LOW"

    if label:
        return f"[{bar}] {entropy:.2f}  {status}  {label}"
    else:
        return f"[{bar}] {entropy:.2f}  {status}"


# ============================================================
# STANDALONE TEST
# Run this file directly to test entropy calculation.
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("  ENTROPY - Entropy Calculator Test")
    print("=" * 60)
    print()

    # ── Test 1: Calculate entropy of different data types ──
    print("TEST 1: Basic Entropy Calculation")
    print("-" * 40)

    test_cases = [
        # (description, data)
        ("All zeros (min entropy)",
         bytes([0] * 1000)),

        ("All same byte",
         bytes([65] * 1000)),

        ("Simple English text",
         b"Hello world this is a normal text file " * 25),

        ("Structured data (repeating)",
         bytes([i % 16 for i in range(1000)])),

        ("Random-looking data (simulated encrypted)",
         bytes([i % 256 for i in range(1000)])),

        ("High entropy (all 256 values equally)",
         bytes(list(range(256)) * 4)),
    ]

    for description, data in test_cases:
        entropy = calculate_entropy(data)
        bar = visualize_entropy(entropy, description)
        print(f"  {bar}")

    print()

    # ── Test 2: Create real test files and measure them ────
    print("TEST 2: Real File Entropy Measurement")
    print("-" * 40)

    test_dir = config.TESTING_DATA_DIR
    os.makedirs(test_dir, exist_ok=True)

    # Create test files
    test_files = []

    # File 1: Plain text (low entropy)
    f1 = os.path.join(test_dir, "test_normal.txt")
    with open(f1, 'w') as f:
        f.write("Hello world. " * 500)
    test_files.append(("Normal text file", f1))

    # File 2: Structured data (medium entropy)
    f2 = os.path.join(test_dir, "test_structured.dat")
    with open(f2, 'wb') as f:
        f.write(bytes([i % 64 for i in range(10000)]))
    test_files.append(("Structured data", f2))

    # File 3: Simulated encrypted (high entropy)
    # We use os.urandom() which produces random bytes
    # This simulates what encrypted file content looks like
    f3 = os.path.join(test_dir, "test_encrypted_sim.dat")
    with open(f3, 'wb') as f:
        f.write(os.urandom(10000))
    test_files.append(("Simulated encrypted (random bytes)", f3))

    # File 4: Mixed content (partly encrypted simulation)
    f4 = os.path.join(test_dir, "test_mixed.dat")
    with open(f4, 'wb') as f:
        f.write(b"Normal header content. " * 50)   # normal start
        f.write(os.urandom(8000))                   # encrypted end
    test_files.append(("Mixed (normal start, encrypted end)", f4))

    # Measure entropy of each file
    analyzer = EntropyAnalyzer()

    for description, filepath in test_files:
        result = analyzer.analyze(filepath)
        print(f"\n  File: {description}")
        print(f"  Path: {os.path.basename(filepath)}")
        print(f"  Size: {result['file_size']} bytes")

        bar = visualize_entropy(result['entropy_overall'])
        print(f"  Overall:  {bar}")

        bar_s = visualize_entropy(result['entropy_start'])
        bar_m = visualize_entropy(result['entropy_middle'])
        bar_e = visualize_entropy(result['entropy_end'])
        print(f"  Start:    {bar_s}")
        print(f"  Middle:   {bar_m}")
        print(f"  End:      {bar_e}")

        print(f"  Suspicious: {result['is_suspicious']}")
        print(f"  Threat Score: {result['threat_score']}/100")
        if result['reason']:
            print(f"  Reason: {result['reason']}")

    print()

    # ── Test 3: Simulate entropy CHANGE (ransomware effect) ─
    print()
    print("TEST 3: Entropy Change Detection")
    print("-" * 40)
    print("Simulating ransomware encrypting a file...")
    print()

    # Create a normal file
    target = os.path.join(test_dir, "target_file.txt")
    with open(target, 'w') as f:
        f.write("This is a normal document. " * 200)

    # First reading (normal)
    result1 = analyzer.analyze(target)
    print(f"  BEFORE encryption:")
    print(f"  {visualize_entropy(result1['entropy_overall'], 'target_file.txt')}")
    print(f"  Suspicious: {result1['is_suspicious']}")

    print()
    print("  [Simulating ransomware encrypting the file...]")
    time.sleep(1)

    # Simulate encryption: overwrite with random bytes
    with open(target, 'wb') as f:
        f.write(os.urandom(10000))

    # Second reading (after "encryption")
    result2 = analyzer.analyze(target)
    print()
    print(f"  AFTER encryption:")
    print(f"  {visualize_entropy(result2['entropy_overall'], 'target_file.txt')}")
    print(f"  Entropy delta: {result2['entropy_delta']:+.2f}")
    print(f"  Suspicious: {result2['is_suspicious']}")
    print(f"  Threat Score: {result2['threat_score']}/100")
    print(f"  Reason: {result2['reason']}")

    print()
    print("=" * 60)
    print("  Entropy Calculator Test Complete")
    print("=" * 60)
    print()
    print("Test files created in:")
    print(f"  {test_dir}")
    print()
    print("Next step: Connect entropy calculator to file monitor")