# Define color codes as constants for easier use
class Colors:
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    RESET = '\033[0m' # Resets the color

print(f"{Colors.RED}This text is red!{Colors.RESET}")
print(f"{Colors.GREEN}This text is green!{Colors.RESET}")
print("This text is normal again.")
