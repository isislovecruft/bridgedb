safe_logging = True

def set_safe_logging(safe):
    global safe_logging
    safe_logging = safe

def logSafely(val):
    if safe_logging:
        return "[scrubbed]"
    else:
        return val

