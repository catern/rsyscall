import os

def raise_if_error(response: int) -> None:
    "Raise an OSError if this integer is in the error range for syscall return values"
    if -4095 < response < 0:
        err = -response
        raise OSError(err, os.strerror(err))
