#!/usr/bin/env python3
"""
Logging demonstration script for the OAuth2 service.

This script demonstrates various logging features:
- Structured logging with JSON format
- Security filtering for sensitive data
- Request context logging
- Different log levels and loggers
- Custom log events for auth and API
"""

import os
import sys
import time
from uuid import uuid4

# Add the parent directory to the path so we can import app modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.core.logging import (
    setup_logging,
    get_logger,
    LogContext,
    log_function_call,
    log_api_request,
    log_api_response,
    log_auth_event,
    log_security_event,
    LoggerMixin
)


class DemoService(LoggerMixin):
    """Demo service class using the LoggerMixin."""
    
    def __init__(self):
        self.logger.info("DemoService initialized")
    
    @log_function_call
    def process_user_data(self, user_id: str, email: str, password: str = "secret123"):
        """Demo method that processes user data (with sensitive info that should be masked)."""
        self.logger.info(
            f"Processing user data for {email}",
            extra={
                'user_id': user_id,
                'email': email,
                'password': password,  # This should be masked by SecurityFilter
                'operation': 'process_user_data'
            }
        )
        
        # Simulate some work
        time.sleep(0.1)
        
        return {"status": "processed", "user_id": user_id}


def demo_basic_logging():
    """Demonstrate basic logging functionality."""
    print("\n=== Demo: Basic Logging ===")
    
    logger = get_logger('demo.basic')
    
    logger.debug("Debug message - usually not shown in production")
    logger.info("Info message - general information")
    logger.warning("Warning message - something might be wrong")
    logger.error("Error message - something went wrong")
    
    # Log with structured data
    logger.info(
        "User action performed",
        extra={
            'user_id': 'user-123',
            'action': 'login',
            'ip_address': '192.168.1.100',
            'timestamp': time.time()
        }
    )


def demo_security_filtering():
    """Demonstrate security filtering of sensitive data."""
    print("\n=== Demo: Security Filtering ===")
    
    logger = get_logger('demo.security')
    
    # These messages contain sensitive data that should be masked
    logger.info("User login with password: secret123")
    logger.info("Token generated: bearer abc123token")
    logger.info("API key usage: api_key=sk-1234567890")
    
    # Structured logging with sensitive fields
    logger.info(
        "Authentication attempt",
        extra={
            'email': 'user@example.com',
            'password': 'mysecretpassword',  # Should be masked
            'token': 'bearer-token-xyz',     # Should be masked
            'client_secret': 'secret-key',   # Should be masked
            'success': True
        }
    )


def demo_request_context():
    """Demonstrate request context logging."""
    print("\n=== Demo: Request Context Logging ===")
    
    request_id = str(uuid4())
    user_id = 'user-456'
    
    # Log API request and response
    log_api_request(request_id, 'POST', '/api/v1/users', user_id)
    
    # Simulate API processing with context
    with LogContext(request_id=request_id, user_id=user_id):
        logger = get_logger('demo.api')
        logger.info("Processing API request")
        logger.info("Validating user data")
        logger.info("Creating user in database")
        
        # Simulate processing time
        time.sleep(0.05)
    
    # Log response
    log_api_response(request_id, 201, 50.5, user_id)


def demo_auth_events():
    """Demonstrate authentication event logging."""
    print("\n=== Demo: Authentication Events ===")
    
    # Successful login
    log_auth_event(
        'login_success',
        user_id='user-789',
        email='user@example.com',
        ip_address='192.168.1.100',
        user_agent='Mozilla/5.0...'
    )
    
    # Failed login
    log_auth_event(
        'login_failure',
        email='hacker@evil.com',
        reason='invalid_password',
        ip_address='10.0.0.1',
        attempts=3
    )
    
    # OAuth login
    log_auth_event(
        'oauth_login',
        user_id='user-789',
        email='user@example.com',
        provider='google',
        sub='google-123456789'
    )


def demo_security_events():
    """Demonstrate security event logging."""
    print("\n=== Demo: Security Events ===")
    
    # Suspicious activity
    log_security_event(
        'suspicious_activity',
        user_id='user-999',
        details='Multiple failed login attempts',
        ip_address='suspicious.ip.address',
        attempt_count=10
    )
    
    # Rate limiting
    log_security_event(
        'rate_limit_exceeded',
        ip_address='192.168.1.200',
        endpoint='/api/v1/auth/login',
        limit=100,
        window='1h'
    )


def demo_class_with_mixin():
    """Demonstrate class with LoggerMixin."""
    print("\n=== Demo: Class with LoggerMixin ===")
    
    service = DemoService()
    
    # Call method that has sensitive data
    result = service.process_user_data(
        user_id='user-123',
        email='demo@example.com',
        password='supersecret'
    )
    
    service.logger.info("Operation completed", extra={'result': result})


def demo_different_formats():
    """Demonstrate different log formats."""
    print("\n=== Demo: Different Log Formats ===")
    
    # Set environment variables to change format
    original_format = os.getenv('LOG_FORMAT')
    
    print("\n--- JSON Format ---")
    os.environ['LOG_FORMAT'] = 'json'
    setup_logging()  # Reconfigure with JSON format
    logger = get_logger('demo.format')
    logger.info("This is a JSON formatted message", extra={'format': 'json', 'demo': True})
    
    print("\n--- Text Format ---")
    os.environ['LOG_FORMAT'] = 'text'
    setup_logging()  # Reconfigure with text format
    logger = get_logger('demo.format')
    logger.info("This is a text formatted message", extra={'format': 'text', 'demo': True})
    
    # Restore original format
    if original_format:
        os.environ['LOG_FORMAT'] = original_format
    else:
        os.environ.pop('LOG_FORMAT', None)


def main():
    """Run all logging demonstrations."""
    print("OAuth2 Service Logging Demonstration")
    print("=" * 50)
    
    # Setup logging with environment variables
    # You can set LOG_LEVEL=DEBUG and LOG_FORMAT=json before running this script
    setup_logging()
    
    # Run demonstrations
    demo_basic_logging()
    demo_security_filtering()
    demo_request_context()
    demo_auth_events()
    demo_security_events()
    demo_class_with_mixin()
    demo_different_formats()
    
    print("\n=== Log Files ===")
    print("Check the 'logs/' directory for log files:")
    print("- oauth2-service-rotating.log (main log file)")
    print("- oauth2-service.log (basic log file)")
    
    print("\n=== Environment Variables ===")
    print("You can customize logging behavior with these environment variables:")
    print("- LOG_LEVEL: DEBUG, INFO, WARNING, ERROR, CRITICAL")
    print("- LOG_FORMAT: json, text")
    print("- ENVIRONMENT: development, staging, production")
    print("- APP_VERSION: 1.0.0, 2.0.0, etc.")
    
    print("\nDemo completed! Check the log files and console output.")


if __name__ == '__main__':
    main() 