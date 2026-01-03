terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  
  backend "s3" {
    bucket         = "techcorp-terraform-state"
    key            = "production/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Environment = var.environment
      Project     = "TechCorp AI Platform"
      ManagedBy   = "Terraform"
      CostCenter  = "Engineering"
    }
  }
}

# VPC Module
module "vpc" {
  source = "./modules/vpc"
  
  environment         = var.environment
  vpc_cidr           = var.vpc_cidr
  availability_zones = var.availability_zones
  
  tags = var.tags
}

# ECS Cluster Module
module "ecs" {
  source = "./modules/ecs"
  
  environment    = var.environment
  cluster_name   = "techcorp-${var.environment}"
  vpc_id         = module.vpc.vpc_id
  private_subnets = module.vpc.private_subnet_ids
  
  tags = var.tags
}

# RDS Database Module
module "rds" {
  source = "./modules/rds"
  
  environment          = var.environment
  instance_class       = var.db_instance_class
  allocated_storage    = var.db_allocated_storage
  database_name        = "techcorp"
  master_username      = var.db_master_username
  vpc_id              = module.vpc.vpc_id
  database_subnet_ids = module.vpc.database_subnet_ids
  
  tags = var.tags
}

# ElastiCache Redis Module
module "redis" {
  source = "./modules/redis"
  
  environment     = var.environment
  node_type       = var.redis_node_type
  num_cache_nodes = var.redis_num_nodes
  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnet_ids
  
  tags = var.tags
}

# S3 Buckets Module
module "s3" {
  source = "./modules/s3"
  
  environment = var.environment
  
  buckets = {
    customer_data = {
      name       = "techcorp-customer-data-${var.environment}"
      versioning = true
      encryption = true
    }
    backups = {
      name       = "techcorp-backups-${var.environment}"
      versioning = true
      encryption = true
      lifecycle  = true
    }
    logs = {
      name       = "techcorp-logs-${var.environment}"
      versioning = false
      encryption = true
      lifecycle  = true
    }
  }
  
  tags = var.tags
}

# Security Module (WAF, GuardDuty, Security Hub)
module "security" {
  source = "./modules/security"
  
  environment = var.environment
  vpc_id      = module.vpc.vpc_id
  
  enable_guardduty    = true
  enable_security_hub = true
  enable_waf          = true
  
  tags = var.tags
}

# KMS Keys Module
module "kms" {
  source = "./modules/kms"
  
  environment = var.environment
  
  keys = {
    database = {
      description = "Encryption key for RDS database"
      rotation    = true
    }
    s3 = {
      description = "Encryption key for S3 buckets"
      rotation    = true
    }
    secrets = {
      description = "Encryption key for Secrets Manager"
      rotation    = true
    }
  }
  
  tags = var.tags
}

# Outputs
output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "ecs_cluster_name" {
  description = "ECS Cluster Name"
  value       = module.ecs.cluster_name
}

output "rds_endpoint" {
  description = "RDS Endpoint"
  value       = module.rds.endpoint
  sensitive   = true
}

output "redis_endpoint" {
  description = "Redis Endpoint"
  value       = module.redis.endpoint
  sensitive   = true
}
