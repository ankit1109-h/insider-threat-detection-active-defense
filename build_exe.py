import os
import subprocess
import sys

def build_agent():
    print("[*] Starting PyInstaller build for vm_agent...")
    
    # Ensure PyInstaller is installed
    try:
        import PyInstaller
    except ImportError:
        print("[!] PyInstaller not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
    
    # Define paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    agent_script = os.path.join(base_dir, 'vm_agent', 'agent.py')
    config_dir = os.path.join(base_dir, 'config')
    
    # We want to package as a single directory (--onedir) rather than a single file (--onefile)
    # because it starts up faster and we can easily bundle the config files next to it.
    # However, --onefile is easier to deploy with Inno Setup. Let's use --onefile.
    
    pyinstaller_cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onedir",
        "--windowed", # Run silently without console window
        "--name", "agent",
        "--add-data", f"{config_dir};config",
        "--hidden-import", "win32evtlog",
        "--hidden-import", "win32clipboard",
        "--hidden-import", "win32security",
        "--hidden-import", "psutil",
        "--hidden-import", "requests",
        "--hidden-import", "watchdog",
        "--hidden-import", "PIL.ImageGrab",
        agent_script
    ]
    
    print(f"[*] Running command: {' '.join(pyinstaller_cmd)}")
    subprocess.check_call(pyinstaller_cmd)
    
    print("[+] PyInstaller build complete! Found in 'dist/agent.exe'")

if __name__ == '__main__':
    build_agent()
