"""
Shared pytest configuration. Adds backend/ to sys.path so test files can
import the application modules (db, remediation, monitoring, collectors.*)
the same way main.py does, without needing the package installed.
"""
import sys
import os

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND_DIR))
