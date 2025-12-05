import logging
import sys
import io

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
    file_handler = logging.FileHandler('audit.log', encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    # Create a stream handler to output to the console with UTF-8 encoding
    # This fixes UnicodeEncodeError on Windows console
    stream_handler = logging.StreamHandler(
        io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    )
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)

    # Add the handlers to the logger
    # But first, clear any existing handlers to avoid duplicates
    if logger.hasHandlers():
        logger.handlers.clear()
        
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    logging.info("Logging has been set up.")
