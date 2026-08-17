# Terraform configuration placeholder for cloud deployment
# Supports AWS, GCP, Azure

terraform {
  required_version = ">= 1.5"
}

variable "environment" {
  type    = string
  default = "development"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

# Placeholder outputs
output "api_url" {
  value = "https://api.bbp.${var.environment}.example.com"
}
