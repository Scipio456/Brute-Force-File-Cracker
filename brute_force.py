import itertools
import string
import time
import argparse
import zipfile
import os
import subprocess
try:
    from pypdf2 import PdfReader
except ImportError:
    PdfReader = None

# WARNING: This script is for EDUCATIONAL PURPOSES ONLY.
# Unauthorized use or modification for malicious purposes is strictly prohibited and illegal.
# Use only on files you own or have explicit permission to test.

CHARSET = string.ascii_lowercase + string.ascii_uppercase + string.digits  # a-z, A-Z, 0-9
MAX_LENGTH = 7  # Maximum password length (configurable, keep short for demo)
DELAY = 0.01  # Delay between attempts (seconds, for demo visibility)
OUTPUT_DIR = "extracted_files"  # Directory for extracted ZIP contents

def test_password(file_path: str, guess: str, file_type: str) -> bool:
    """Test if the provided password unlocks the file."""
    if file_type == 'zip':
        try:
            with zipfile.ZipFile(file_path) as zf:
                zf.extractall(pwd=guess.encode('utf-8'), path=OUTPUT_DIR)
            return True
        except:
            return False
    elif file_type == 'pdf':
        if PdfReader is None:
            print("Error: pypdf2 not installed. Install with 'pip install pypdf2' for PDF support.")
            return False
        try:
            reader = PdfReader(file_path)
            reader.decrypt(guess)
            reader.pages[0]  # Access a page to check decryption
            return True
        except:
            return False
    else:
        print("Error: Unsupported file type. Use .zip or .pdf.")
        return False

def open_file(file_path: str, password: str, file_type: str):
    """Open or extract the file after cracking the password."""
    try:
        if file_type == 'zip':
            os.makedirs(OUTPUT_DIR, exist_ok=True)
            with zipfile.ZipFile(file_path) as zf:
                zf.extractall(pwd=password.encode('utf-8'), path=OUTPUT_DIR)
            print(f"ZIP file extracted to '{OUTPUT_DIR}'.")
            # Open the extracted folder on macOS
            subprocess.run(['open', OUTPUT_DIR], check=True)
        elif file_type == 'pdf':
            if PdfReader is None:
                print("Error: pypdf2 not installed. Cannot open PDF.")
                return
            reader = PdfReader(file_path)
            reader.decrypt(password)
            # Extract and print first page text as a demo
            text = reader.pages[0].extract_text() or "No text found on first page."
            print(f"PDF opened. First page text:\n{text[:200]}...")
            # Open PDF with default viewer (Preview on macOS)
            subprocess.run(['open', file_path], check=True)
    except Exception as e:
        print(f"Error opening file: {e}")

def brute_force(file_path: str) -> bool:
    """
    Perform an optimized brute force attack on the file password.
    
    Args:
        file_path (str): Path to the password-protected file.
    
    Returns:
        bool: True if password is found and file is opened, False otherwise.
    """
    file_ext = file_path.lower().split('.')[-1]
    file_type = 'zip' if file_ext == 'zip' else 'pdf' if file_ext == 'pdf' else None
    if not file_type:
        print("Error: Unsupported file type. Use .zip or .pdf.")
        return False

    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        return False

    print("Starting brute force attack demonstration...")
    print(f"Using character set: {CHARSET} (alphanumeric, case-sensitive)")
    print(f"Maximum password length: {MAX_LENGTH}")
    print("NOTE: This is an educational demonstration. Do not use on unauthorized files.")
    print("Warning: Brute forcing long passwords is slow (e.g., 62^7 ≈ 3.5T combinations). Use short passwords for demo.")

    attempts = 0
    start_time = time.time()
    print_interval = 1000  # Show progress every 1000 attempts

    for length in range(1, MAX_LENGTH + 1):
        for tuple_guess in itertools.product(CHARSET, repeat=length):
            attempts += 1
            guess = ''.join(tuple_guess)
            if attempts % print_interval == 0:
                print(f"Attempt #{attempts}: Trying passwords of length {length} (current: {guess})")
            time.sleep(DELAY)  # Simulate real-world delay
            if test_password(file_path, guess, file_type):
                end_time = time.time()
                print(f"\nSuccess! Password found: {guess}")
                print(f"Attempts: {attempts}")
                print(f"Time taken: {end_time - start_time:.2f} seconds")
                open_file(file_path, guess, file_type)
                return True
    print("\nFailed to find password within constraints.")
    return False

def main():
    """Main function to handle command-line arguments and run the brute force demo."""
    parser = argparse.ArgumentParser(description="Educational brute force file password cracker demo.")
    parser.add_argument(
        "--file",
        type=str,
        help="Path to the password-protected file (e.g., test.zip or test.pdf)",
        required=True
    )
    args = parser.parse_args()
    
    try:
        print("WARNING: This tool is for EDUCATIONAL USE ONLY. Unauthorized use is illegal.")
        brute_force(args.file)
    except KeyboardInterrupt:
        print("\nBrute force attack stopped by user.")

if __name__ == "__main__":
    main()