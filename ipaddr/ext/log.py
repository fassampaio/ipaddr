import logging


def init_app(app):
    """
        Configures the system logging parameters
        Logging level: NOTSET=0, DEBUG=10, INFO=20, WARN=30, ERROR=40, and CRITICAL=50.
    """
    log_level = app.config['LOGGING_LEVEL']
    log_file = app.config['LOGGING_FILE_URI']
    logging.basicConfig(
        level=log_level,
        handlers=[
            # logging.StreamHandler(sys.stdout),
            logging.FileHandler(f'{log_file}', encoding='UTF-8')
        ]
    )
