import logging
import sys

def setup_logging():
    """
    Set up a centralized logger for the application.
    """
    # Get the root logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Create a formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create a file handler
    file_handler = logging.FileHandler('audit.log')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    # Create a stream handler to output to the console
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)

    # Add the handlers to the logger
    # But first, clear any existing handlers to avoid duplicates
    if logger.hasHandlers():
        logger.handlers.clear()
        
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    logging.info("Logging has been set up.")
