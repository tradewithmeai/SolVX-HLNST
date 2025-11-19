"""Central logging configuration with structured logs."""

import logging
import logging.handlers
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
import json


class JSONFormatter(logging.Formatter):
    """Format logs as JSON for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields if present
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)

        return json.dumps(log_data)


class ColoredFormatter(logging.Formatter):
    """Colorized formatter for console output."""

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        """Format with colors."""
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.RESET}"
        return super().format(record)


def setup_logging(
    level: str = "INFO",
    log_dir: Optional[Path] = None,
    console: bool = True,
    json_logs: bool = True,
) -> None:
    """
    Setup application logging.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: Directory for log files. If None, logs only to console
        console: Whether to log to console
        json_logs: Whether to use JSON format for file logs
    """
    root_logger = logging.getLogger("solvx_net")
    root_logger.setLevel(getattr(logging, level.upper()))
    root_logger.handlers.clear()

    # Console handler with colored output
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, level.upper()))
        console_formatter = ColoredFormatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

    # File handlers
    if log_dir:
        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)

        # Regular text log
        text_handler = logging.handlers.RotatingFileHandler(
            log_dir / "solvx.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
        )
        text_handler.setLevel(getattr(logging, level.upper()))
        text_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        text_handler.setFormatter(text_formatter)
        root_logger.addHandler(text_handler)

        # JSON log for structured data
        if json_logs:
            json_handler = logging.handlers.RotatingFileHandler(
                log_dir / "solvx.jsonl",
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5,
            )
            json_handler.setLevel(getattr(logging, level.upper()))
            json_handler.setFormatter(JSONFormatter())
            root_logger.addHandler(json_handler)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(f"solvx_net.{name}")
