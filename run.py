import sys
import os

# Add src to path so we can import credx_v2
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

from credx_v2.__main__ import main

if __name__ == "__main__":
    main()
