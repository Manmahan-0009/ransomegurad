"""
RansomGuard - Sandbox Reset Wrapper Script

Thin wrapper around utils.sandbox_manager.reset_sandbox.
Allows running `python reset_sandbox.py` directly from the project root.
"""

from utils.sandbox_manager import reset_sandbox

if __name__ == "__main__":
    reset_sandbox()
