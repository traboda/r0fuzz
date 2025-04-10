import os
import logging


def get_logger(name: str, level: int) -> logging.Logger:
    """Returns a Logger instance for a file.

    Args:
        name (str): Name of the logger
        level (int): Debug level
                    (0 -> Error, 1 -> Info, other -> Debug)

    Returns:
        logging.Logger: Logger Object
    """
    os.makedirs("logs", exist_ok=True)

    logger = logging.getLogger(name)

    if level == 0:
        logger.setLevel(logging.ERROR)
    elif level == 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.DEBUG)

    # Avoid duplicate handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    stream_h = logging.StreamHandler()
    file_h = logging.FileHandler(f"logs/{name}.log")

    formatter = logging.Formatter("[*] %(message)s")

    stream_h.setFormatter(formatter)
    file_h.setFormatter(formatter)

    logger.addHandler(stream_h)
    logger.addHandler(file_h)

    return logger
