from constants import LOG_FILE

log = open(LOG_FILE, "w")

def write_log(message):
    log.write(message + "\n")

def close_log():
    log.close()