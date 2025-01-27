from pathlib import Path
from Infra.util import *
import time, os
import login, configs

def disable_keyboard():
    #ensure_installed(Path('Null_Keyboard-one.apk'))
    os.system(f"adb install -r Null_Keyboard-one.apk")
    adb_exec("ime set com.wparam.nullkeyboard/.NullKeyboard", 2)

def setup_device():
    disable_keyboard()

def setup_app(apk):
    ensure_reinstalled(apk)
    start_app(apk)
    time.sleep(10)
    return login.login_app(apk)

if __name__ == '__main__':
    setup_device()
