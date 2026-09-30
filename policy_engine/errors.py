class PolicyConfigurationError(ValueError):
    """Raised when the security policy configuration is invalid."""


class ReportValidationError(ValueError):
    """Raised when a scanner report cannot be safely parsed."""
