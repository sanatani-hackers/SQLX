#!/usr/bin/env python3
import sys

# Ensure the sqlx package is in the path if run directly
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlx.ui.console import main

if __name__ == "__main__":
    main()
