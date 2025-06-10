#!/usr/bin/env python3
"""Test runner script for the OAuth2 service."""

import sys
import subprocess


def main():
    """Run tests with pytest."""
    cmd = ["python", "-m", "pytest", "tests/", "-v"]
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--coverage":
            cmd.extend(["--cov=app", "--cov-report=html"])
        elif sys.argv[1] == "--users":
            cmd = ["python", "-m", "pytest", "tests/test_users.py", "-v"]
        elif sys.argv[1] == "--rbac":
            cmd = ["python", "-m", "pytest", "tests/test_rbac.py", "-v"]
    
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main()) 