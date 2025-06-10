"""
Logging configuration for the OAuth2 service.

This module provides centralized logging setup with support for:
- Structured JSON logging
- Multiple handlers (console, file, rotating file)
- Environment-based configuration
- Integration with FastAPI/uvicorn
- Security-aware logging (PII filtering)
"""

import logging
import logging.config
import sys
from pathlib import Path
from typing import Any, Dict, Optional
import json
from datetime import datetime
import os

from pythonjsonlogger import jsonlogger


class SecurityFilter(logging.Filter):
    """Filter to remove or mask sensitive information from logs."""
    
    SENSITIVE_FIELDS = {
        'password', 'token', 'secret', 'key', 'authorization', 
        'cookie', 'csrf_token', 'api_key', 'refresh_token', 
        'access_token', 'client_secret'
    }
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter sensitive information from log records."""
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            record.msg = self._mask_sensitive_data(record.msg)
        
        if hasattr(record, 'args') and record.args:
            record.args = tuple(
                self._mask_sensitive_data(str(arg)) if isinstance(arg, str) else arg 
                for arg in record.args
            )
        
        return True
    
    def _mask_sensitive_data(self, text: str) -> str:
        """Mask sensitive data in text."""
        for field in self.SENSITIVE_FIELDS:
            if field.lower() in text.lower():
                # Simple masking - in production, use more sophisticated regex
                text = text.replace(field, f"{field}=***MASKED***")
        return text


class CustomJSONFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter with additional fields."""
    
    def add_fields(self, log_record: Dict[str, Any], record: logging.LogRecord, message_dict: Dict[str, Any]) -> None:
        """Add custom fields to log record."""
        super().add_fields(log_record, record, message_dict)
        
        # Add timestamp
        log_record['timestamp'] = datetime.utcnow().isoformat()
        
        # Add service information
        log_record['service'] = 'oauth2-service'
        log_record['version'] = os.getenv('APP_VERSION', '1.0.0')
        log_record['environment'] = os.getenv('ENVIRONMENT', 'development')
        
        # Add request context if available
        if hasattr(record, 'request_id'):
            log_record['request_id'] = record.request_id
        
        if hasattr(record, 'user_id'):
            log_record['user_id'] = record.user_id
        
        # Ensure level is always present
        if not log_record.get('level'):
            log_record['level'] = record.levelname


class RequestContextFilter(logging.Filter):
    """Filter to add request context to log records."""
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Add request context to log records."""
        # This would be populated by middleware in a real application
        # For now, we'll just ensure the attributes exist
        if not hasattr(record, 'request_id'):
            record.request_id = None
        if not hasattr(record, 'user_id'):
            record.user_id = None
        return True


def get_log_level() -> str:
    """Get log level from environment variable."""
    return os.getenv('LOG_LEVEL', 'INFO').upper()


def get_log_format() -> str:
    """Get log format from environment variable."""
    return os.getenv('LOG_FORMAT', 'json')  # 'json' or 'text'


def ensure_log_directory() -> Path:
    """Ensure log directory exists."""
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    return log_dir


def get_logging_config(
    log_level: Optional[str] = None,
    log_format: Optional[str] = None,
    log_file: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get logging configuration dictionary.
    
    Args:
        log_level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Log format ('json' or 'text')
        log_file: Log file path
    
    Returns:
        Logging configuration dictionary
    """
    log_level = log_level or get_log_level()
    log_format = log_format or get_log_format()
    
    # Ensure log directory exists
    log_dir = ensure_log_directory()
    
    if not log_file:
        log_file = log_dir / 'oauth2-service.log'
    
    # Define formatters
    formatters = {
        'detailed_text': {
            'format': '[{asctime}] [{levelname}] [{name}] [{funcName}:{lineno}] - {message}',
            'style': '{',
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
        'simple_text': {
            'format': '[{asctime}] [{levelname}] - {message}',
            'style': '{',
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
        'json': {
            '()': CustomJSONFormatter,
            'format': '%(asctime)s %(name)s %(levelname)s %(message)s'
        }
    }
    
    # Define handlers
    handlers = {
        'console': {
            'class': 'logging.StreamHandler',
            'level': log_level,
            'formatter': 'json' if log_format == 'json' else 'detailed_text',
            'stream': 'ext://sys.stdout',
            'filters': ['security_filter', 'request_context']
        },
        'file': {
            'class': 'logging.FileHandler',
            'level': log_level,
            'formatter': 'json' if log_format == 'json' else 'detailed_text',
            'filename': str(log_file),
            'mode': 'a',
            'encoding': 'utf-8',
            'filters': ['security_filter', 'request_context']
        },
        'rotating_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': log_level,
            'formatter': 'json' if log_format == 'json' else 'detailed_text',
            'filename': str(log_dir / 'oauth2-service-rotating.log'),
            'maxBytes': 10 * 1024 * 1024,  # 10MB
            'backupCount': 5,
            'encoding': 'utf-8',
            'filters': ['security_filter', 'request_context']
        }
    }
    
    # Define filters
    filters = {
        'security_filter': {
            '()': SecurityFilter,
        },
        'request_context': {
            '()': RequestContextFilter,
        }
    }
    
    # Define loggers
    loggers = {
        'app': {
            'level': log_level,
            'handlers': ['console', 'rotating_file'],
            'propagate': False
        },
        'app.auth': {
            'level': log_level,
            'handlers': ['console', 'rotating_file'],
            'propagate': False
        },
        'app.users': {
            'level': log_level,
            'handlers': ['console', 'rotating_file'],
            'propagate': False
        },
        'app.rbac': {
            'level': log_level,
            'handlers': ['console', 'rotating_file'],
            'propagate': False
        },
        'uvicorn': {
            'level': 'INFO',
            'handlers': ['console'],
            'propagate': False
        },
        'uvicorn.access': {
            'level': 'INFO',
            'handlers': ['console', 'file'],
            'propagate': False
        },
        'sqlalchemy.engine': {
            'level': 'WARNING',  # Reduce SQL query noise
            'handlers': ['rotating_file'],
            'propagate': False
        }
    }
    
    config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': formatters,
        'filters': filters,
        'handlers': handlers,
        'loggers': loggers,
        'root': {
            'level': log_level,
            'handlers': ['console', 'rotating_file']
        }
    }
    
    return config


def setup_logging(
    log_level: Optional[str] = None,
    log_format: Optional[str] = None,
    log_file: Optional[str] = None
) -> None:
    """
    Setup logging configuration.
    
    Args:
        log_level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Log format ('json' or 'text')
        log_file: Log file path
    """
    config = get_logging_config(log_level, log_format, log_file)
    logging.config.dictConfig(config)
    
    # Log startup message
    logger = logging.getLogger('app')
    logger.info(
        "Logging configured successfully",
        extra={
            'log_level': log_level or get_log_level(),
            'log_format': log_format or get_log_format(),
            'environment': os.getenv('ENVIRONMENT', 'development')
        }
    )


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the specified name.
    
    Args:
        name: Logger name (usually __name__)
    
    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)


class LoggerMixin:
    """Mixin class to add logging capabilities to other classes."""
    
    @property
    def logger(self) -> logging.Logger:
        """Get logger for this class."""
        return get_logger(self.__class__.__module__)


# Context managers for structured logging

class LogContext:
    """Context manager for adding structured context to logs."""
    
    def __init__(self, **context):
        self.context = context
        self.original_factory = logging.getLogRecordFactory()
    
    def __enter__(self):
        def record_factory(*args, **kwargs):
            record = self.original_factory(*args, **kwargs)
            for key, value in self.context.items():
                setattr(record, key, value)
            return record
        
        logging.setLogRecordFactory(record_factory)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        logging.setLogRecordFactory(self.original_factory)


# Convenience functions for common logging patterns

def log_function_call(func):
    """Decorator to log function calls."""
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        logger.debug(
            f"Calling function: {func.__name__}",
            extra={
                'function_name': func.__name__,
                'function_module': func.__module__,
                'args_count': len(args),
                'kwargs_keys': list(kwargs.keys())
            }
        )
        
        try:
            result = func(*args, **kwargs)
            logger.debug(
                f"Function completed: {func.__name__}",
                extra={
                    'function_name': func.__name__,
                    'function_module': func.__module__,
                    'success': True
                }
            )
            return result
        except Exception as e:
            logger.error(
                f"Function failed: {func.__name__}",
                extra={
                    'function_name': func.__name__,
                    'function_module': func.__module__,
                    'error': str(e),
                    'error_type': type(e).__name__
                },
                exc_info=True
            )
            raise
    
    return wrapper


def log_api_request(request_id: str, method: str, path: str, user_id: Optional[str] = None):
    """Log API request with structured data."""
    logger = get_logger('app.api')
    logger.info(
        "API request received",
        extra={
            'request_id': request_id,
            'method': method,
            'path': path,
            'user_id': user_id,
            'event_type': 'api_request'
        }
    )


def log_api_response(request_id: str, status_code: int, duration_ms: float, user_id: Optional[str] = None):
    """Log API response with structured data."""
    logger = get_logger('app.api')
    logger.info(
        "API request completed",
        extra={
            'request_id': request_id,
            'status_code': status_code,
            'duration_ms': duration_ms,
            'user_id': user_id,
            'event_type': 'api_response'
        }
    )


def log_security_event(event_type: str, user_id: Optional[str] = None, **details):
    """Log security-related events."""
    logger = get_logger('app.security')
    logger.warning(
        f"Security event: {event_type}",
        extra={
            'event_type': 'security_event',
            'security_event_type': event_type,
            'user_id': user_id,
            **details
        }
    )


def log_auth_event(event_type: str, user_id: Optional[str] = None, email: Optional[str] = None, **details):
    """Log authentication-related events."""
    logger = get_logger('app.auth')
    logger.info(
        f"Auth event: {event_type}",
        extra={
            'event_type': 'auth_event',
            'auth_event_type': event_type,
            'user_id': user_id,
            'email': email,
            **details
        }
    )
