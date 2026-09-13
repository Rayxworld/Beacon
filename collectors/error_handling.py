"""
Enhanced logging and error handling utilities for Beacon collectors.
Provides structured logging, retry logic, and detailed error context.
"""

import logging
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar, cast


# Configure structured logging
class StructuredFormatter(logging.Formatter):
    """JSON-compatible structured logging formatter."""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else "Unknown",
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_exc(),
            }
        
        if hasattr(record, 'extra_data'):
            log_data.update(record.extra_data)
        
        return str(log_data)


def setup_logging(name: str, log_dir: Optional[Path] = None, level: int = logging.INFO) -> logging.Logger:
    """
    Configure structured logging for a collector module.
    
    Args:
        name: Logger name (typically __name__)
        log_dir: Directory to write logs to (optional)
        level: Logging level (default INFO)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(StructuredFormatter())
    logger.addHandler(console_handler)
    
    # File handler (if log_dir specified)
    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(
            log_dir / f"{name.replace('.', '_')}.log",
            encoding="utf-8"
        )
        file_handler.setFormatter(StructuredFormatter())
        logger.addHandler(file_handler)
    
    return logger


T = TypeVar('T')


def retry_with_backoff(
    max_retries: int = 3,
    initial_delay: float = 1.0,
    backoff_factor: float = 2.0,
    jitter: bool = True,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator for retry logic with exponential backoff.
    
    Args:
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay between retries (seconds)
        backoff_factor: Multiplier for delay (exponential)
        jitter: Add random jitter to avoid thundering herd
    
    Returns:
        Decorated function with retry capability
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        logger = logging.getLogger(func.__module__)
        
        def wrapper(*args: Any, **kwargs: Any) -> T:
            import random
            import time
            
            delay = initial_delay
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    if attempt == max_retries:
                        logger.error(
                            f"Failed after {max_retries + 1} attempts: {func.__name__}",
                            extra={"extra_data": {
                                "function": func.__name__,
                                "error": str(e),
                                "attempts": max_retries + 1
                            }}
                        )
                        raise
                    
                    # Calculate backoff with optional jitter
                    backoff_delay = delay * (backoff_factor ** attempt)
                    if jitter:
                        backoff_delay += random.uniform(0, backoff_delay * 0.1)
                    
                    logger.warning(
                        f"Attempt {attempt + 1}/{max_retries + 1} failed for {func.__name__}, "
                        f"retrying in {backoff_delay:.2f}s",
                        extra={"extra_data": {
                            "function": func.__name__,
                            "attempt": attempt + 1,
                            "max_retries": max_retries + 1,
                            "error": str(e),
                            "next_delay": backoff_delay
                        }}
                    )
                    time.sleep(backoff_delay)
            
            # Should not reach here, but just in case
            if last_exception:
                raise last_exception
        
        return cast(Callable[..., T], wrapper)
    
    return decorator


class CollectorError(Exception):
    """Base exception for collector errors."""
    
    def __init__(
        self,
        message: str,
        error_code: str,
        context: Optional[dict[str, Any]] = None,
        original_exception: Optional[Exception] = None,
    ):
        self.message = message
        self.error_code = error_code
        self.context = context or {}
        self.original_exception = original_exception
        super().__init__(message)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert error to dictionary for logging."""
        return {
            "error_code": self.error_code,
            "message": self.message,
            "context": self.context,
            "original_error": str(self.original_exception) if self.original_exception else None,
        }


class CertificateTransparencyError(CollectorError):
    """Error during Certificate Transparency collection."""
    pass


class DNSCollectionError(CollectorError):
    """Error during DNS record collection."""
    pass


class SubdomainEnumerationError(CollectorError):
    """Error during subdomain enumeration."""
    pass


class InternetDBError(CollectorError):
    """Error during InternetDB enrichment."""
    pass


class DataValidationError(CollectorError):
    """Error during data validation."""
    pass


def validate_domain(domain: str, context: str = "unknown") -> str:
    """
    Validate and normalize a domain.
    
    Args:
        domain: Domain to validate
        context: Context for error logging
    
    Returns:
        Normalized domain
    
    Raises:
        DataValidationError: If domain is invalid
    """
    logger = logging.getLogger(__name__)
    
    if not domain or not isinstance(domain, str):
        raise DataValidationError(
            f"Invalid domain type: {type(domain)}",
            error_code="INVALID_DOMAIN_TYPE",
            context={"domain": domain, "context": context}
        )
    
    domain = domain.lower().strip()
    
    if not domain or len(domain) < 3:
        raise DataValidationError(
            f"Domain too short: {domain}",
            error_code="DOMAIN_TOO_SHORT",
            context={"domain": domain, "context": context}
        )
    
    if " " in domain or "\n" in domain:
        raise DataValidationError(
            f"Domain contains invalid characters",
            error_code="DOMAIN_INVALID_CHARS",
            context={"domain": domain, "context": context}
        )
    
    return domain


def log_collection_result(
    logger: logging.Logger,
    domain: str,
    collection_type: str,
    success: bool,
    count: Optional[int] = None,
    duration_sec: Optional[float] = None,
    error: Optional[Exception] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    """
    Log structured collection result.
    
    Args:
        logger: Logger instance
        domain: Domain being collected
        collection_type: Type of collection (dns, crtsh, etc.)
        success: Whether collection succeeded
        count: Number of results (if applicable)
        duration_sec: Duration of collection in seconds
        error: Exception if collection failed
        metadata: Additional metadata to log
    """
    log_data = {
        "domain": domain,
        "collection_type": collection_type,
        "success": success,
        "count": count,
        "duration_sec": duration_sec,
    }
    
    if error:
        log_data["error"] = str(error)
        if isinstance(error, CollectorError):
            log_data["error_details"] = error.to_dict()
    
    if metadata:
        log_data.update(metadata)
    
    level = logging.INFO if success else logging.ERROR
    logger.log(
        level,
        f"Collection result for {domain} ({collection_type}): {'success' if success else 'failed'}",
        extra={"extra_data": log_data}
    )
