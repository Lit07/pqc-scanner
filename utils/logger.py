import logging
import sys
import threading
from typing import Dict, Any


_loggers: Dict[str, logging.Logger] = {}
_lock = threading.Lock()


def get_logger(name: str) -> logging.Logger:
    import os
    
    with _lock:
        if name in _loggers:
            return _loggers[name]

        logger = logging.getLogger(name)
        
        if not logger.handlers:
            log_level_str = os.getenv("LOG_LEVEL", "INFO").upper()
            try:
                log_level = getattr(logging, log_level_str)
            except AttributeError:
                log_level = logging.INFO

            logger.setLevel(log_level)
            
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
            
            logger.propagate = False

        _loggers[name] = logger
        return logger
