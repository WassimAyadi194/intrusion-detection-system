from capturing.capture import start_capture
from logs.logger import close_log
from capturing.interface_utils import get_active_interface

def main():
    iface, local_ip = get_active_interface()

    if iface is None:
        raise SystemExit("IDS startup failed: no active interface detected.")

    start_capture(iface, local_ip)
    close_log()

if __name__ == "__main__":
    main()
