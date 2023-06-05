# ---------------------------------------------------------------------------------------------------------------------
# ENVIRONMENT VARIABLES
# Define these secrets as environment variables
# ---------------------------------------------------------------------------------------------------------------------
# AWS_ACCESS_KEY_ID
# AWS_SECRET_ACCESS_KEY
# ---------------------------------------------------------------------------------------------------------------------

# OPTIONAL PARAMETERS
# These parameters have reasonable defaults.
# ---------------------------------------------------------------------------------------------------------------------

variable "test_buildspec" {
  description = "The buildspec to be used for the Test stage (default: buildspec_test.yml)"
  default     = "buildspec.yml"
}

