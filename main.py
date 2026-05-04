# =============================================================
# Encrypted Chat — Main Entry Point
# Run this file to launch the chat application
# =============================================================

import sys
import os

# Make sure all sub-packages are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.chat_window import launch_gui

if __name__ == "__main__":
    launch_gui()