"""CAPEv2 Report Analyzer — entry point"""
import sys
from pathlib import Path

# .env 로드 (없으면 무시)
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass

from gui.app import App

if __name__ == "__main__":
    initial = sys.argv[1] if len(sys.argv) > 1 else None
    app = App(initial_file=initial)
    app.mainloop()
