"""CAPEv2 Report Analyzer — entry point"""
import sys
from gui.app import App

if __name__ == "__main__":
    initial = sys.argv[1] if len(sys.argv) > 1 else None
    app = App(initial_file=initial)
    app.mainloop()
