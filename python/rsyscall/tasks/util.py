import os

def raise_if_error(response: int) -> None:
    "Raise an OSError if this integer is in the error range for syscall return values"
    if -4095 < response < 0:
        err = -response
        raise OSError(err, os.strerror(err))

def log_syscall(logger, number, arg1, arg2, arg3, arg4, arg5, arg6) -> None:
    "Log this syscall prettily"
    if arg6 == 0:
        if arg5 == 0:
            if arg4 == 0:
                if arg3 == 0:
                    if arg2 == 0:
                        if arg1 == 0:
                            logger.debug("%s()", number)
                        else:
                            logger.debug("%s(%s)", number, arg1)
                    else:
                        logger.debug("%s(%s, %s)", number, arg1, arg2)
                else:
                    logger.debug("%s(%s, %s, %s)", number, arg1, arg2, arg3)
            else:
                logger.debug("%s(%s, %s, %s, %s)", number, arg1, arg2, arg3, arg4)
        else:
            logger.debug("%s(%s, %s, %s, %s, %s)", number, arg1, arg2, arg3, arg4, arg5)
    else:
        logger.debug("%s(%s, %s, %s, %s, %s, %s)", number, arg1, arg2, arg3, arg4, arg5, arg6)
