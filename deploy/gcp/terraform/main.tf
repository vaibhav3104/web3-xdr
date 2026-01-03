# =============================================================================
# Web3 XDR - GCP Infrastructure (Terraform)
# =============================================================================
# Deploy with:
#   terraform init
#   terraform plan -var-file="production.tfvars"
#   terraform apply -var-file="production.tfvars"
# =============================================================================

terraform {
  required_version = ">= 1.0.0"
  
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
  
  # Store state in GCS (recommended for production)
  backend "gcs" {
    bucket = "web3-xdr-terraform-state"
    prefix = "production"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# =============================================================================
# Variables
# =============================================================================

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "app_name" {
  description = "Application name"
  type        = string
  default     = "web3-xdr"
}

variable "db_tier" {
  description = "Cloud SQL tier"
  type        = string
  default     = "db-custom-2-4096"
}

variable "min_instances" {
  description = "Minimum Cloud Run instances"
  type        = number
  default     = 1
}

variable "max_instances" {
  description = "Maximum Cloud Run instances"
  type        = number
  default     = 10
}

# =============================================================================
# Enable Required APIs
# =============================================================================

resource "google_project_service" "apis" {
  for_each = toset([
    "run.googleapis.com",
    "sqladmin.googleapis.com",
    "secretmanager.googleapis.com",
    "artifactregistry.googleapis.com",
    "vpcaccess.googleapis.com",
    "servicenetworking.googleapis.com"
  ])
  
  service            = each.key
  disable_on_destroy = false
}

# =============================================================================
# VPC Network
# =============================================================================

resource "google_compute_network" "main" {
  name                    = "${var.app_name}-vpc"
  auto_create_subnetworks = false
  
  depends_on = [google_project_service.apis]
}

resource "google_compute_subnetwork" "main" {
  name          = "${var.app_name}-subnet"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.main.id
}

resource "google_compute_global_address" "private_ip" {
  name          = "${var.app_name}-private-ip"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.main.id
}

resource "google_service_networking_connection" "private_vpc" {
  network                 = google_compute_network.main.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip.name]
}

# VPC Connector for Cloud Run
resource "google_vpc_access_connector" "main" {
  name          = "${var.app_name}-connector"
  region        = var.region
  network       = google_compute_network.main.name
  ip_cidr_range = "10.8.0.0/28"
  
  depends_on = [google_project_service.apis]
}

# =============================================================================
# Cloud SQL (PostgreSQL)
# =============================================================================

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "google_secret_manager_secret" "db_password" {
  secret_id = "${var.app_name}-db-password"
  
  replication {
    auto {}
  }
  
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = random_password.db_password.result
}

resource "google_sql_database_instance" "main" {
  name             = "${var.app_name}-db"
  database_version = "POSTGRES_15"
  region           = var.region
  
  settings {
    tier              = var.db_tier
    availability_type = var.environment == "production" ? "REGIONAL" : "ZONAL"
    disk_size         = 20
    disk_type         = "PD_SSD"
    disk_autoresize   = true
    
    backup_configuration {
      enabled                        = true
      start_time                     = "03:00"
      point_in_time_recovery_enabled = true
      backup_retention_settings {
        retained_backups = 7
      }
    }
    
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.main.id
    }
    
    database_flags {
      name  = "max_connections"
      value = "100"
    }
    
    insights_config {
      query_insights_enabled  = true
      record_application_tags = true
    }
  }
  
  deletion_protection = var.environment == "production"
  
  depends_on = [google_service_networking_connection.private_vpc]
}

resource "google_sql_database" "main" {
  name     = "web3_xdr"
  instance = google_sql_database_instance.main.name
}

resource "google_sql_user" "main" {
  name     = "xdr_admin"
  instance = google_sql_database_instance.main.name
  password = random_password.db_password.result
}

# =============================================================================
# Artifact Registry
# =============================================================================

resource "google_artifact_registry_repository" "main" {
  location      = var.region
  repository_id = var.app_name
  format        = "DOCKER"
  
  depends_on = [google_project_service.apis]
}

# =============================================================================
# Service Account
# =============================================================================

resource "google_service_account" "cloud_run" {
  account_id   = "${var.app_name}-run"
  display_name = "Web3 XDR Cloud Run Service Account"
}

resource "google_project_iam_member" "cloud_run_sql" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

resource "google_secret_manager_secret_iam_member" "cloud_run_secrets" {
  secret_id = google_secret_manager_secret.db_password.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.cloud_run.email}"
}

# =============================================================================
# Cloud Run Service
# =============================================================================

resource "google_cloud_run_v2_service" "main" {
  name     = var.app_name
  location = var.region
  
  template {
    service_account = google_service_account.cloud_run.email
    
    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }
    
    vpc_access {
      connector = google_vpc_access_connector.main.id
      egress    = "PRIVATE_RANGES_ONLY"
    }
    
    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/${var.app_name}/${var.app_name}:latest"
      
      ports {
        container_port = 8080
      }
      
      resources {
        limits = {
          cpu    = "2"
          memory = "2Gi"
        }
      }
      
      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }
      
      env {
        name  = "LOG_LEVEL"
        value = "INFO"
      }
      
      env {
        name  = "POSTGRES_ENABLED"
        value = "true"
      }
      
      env {
        name  = "POSTGRES_HOST"
        value = google_sql_database_instance.main.private_ip_address
      }
      
      env {
        name  = "POSTGRES_PORT"
        value = "5432"
      }
      
      env {
        name  = "POSTGRES_DB"
        value = "web3_xdr"
      }
      
      env {
        name  = "POSTGRES_USER"
        value = "xdr_admin"
      }
      
      env {
        name = "POSTGRES_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.db_password.secret_id
            version = "latest"
          }
        }
      }
      
      env {
        name  = "DB_POOL_SIZE"
        value = "10"
      }
      
      env {
        name  = "DB_BATCH_SIZE"
        value = "100"
      }
      
      startup_probe {
        http_get {
          path = "/health"
          port = 8080
        }
        initial_delay_seconds = 10
        timeout_seconds       = 5
        period_seconds        = 10
        failure_threshold     = 3
      }
      
      liveness_probe {
        http_get {
          path = "/health"
          port = 8080
        }
        period_seconds    = 30
        timeout_seconds   = 5
        failure_threshold = 3
      }
    }
  }
  
  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }
  
  depends_on = [
    google_sql_database.main,
    google_secret_manager_secret_version.db_password
  ]
}

# Allow unauthenticated access (for public dashboard)
resource "google_cloud_run_v2_service_iam_member" "public" {
  name     = google_cloud_run_v2_service.main.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# =============================================================================
# Cloud Monitoring
# =============================================================================

resource "google_monitoring_uptime_check_config" "main" {
  display_name = "${var.app_name}-health-check"
  timeout      = "10s"
  period       = "60s"
  
  http_check {
    path         = "/health"
    port         = 443
    use_ssl      = true
    validate_ssl = true
  }
  
  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = replace(google_cloud_run_v2_service.main.uri, "https://", "")
    }
  }
}

resource "google_monitoring_alert_policy" "uptime" {
  display_name = "${var.app_name}-uptime-alert"
  combiner     = "OR"
  
  conditions {
    display_name = "Uptime Check Failed"
    
    condition_threshold {
      filter          = "resource.type = \"uptime_url\" AND metric.type = \"monitoring.googleapis.com/uptime_check/check_passed\""
      duration        = "300s"
      comparison      = "COMPARISON_LT"
      threshold_value = 1
      
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_FRACTION_TRUE"
      }
    }
  }
  
  notification_channels = []
}

# =============================================================================
# Outputs
# =============================================================================

output "service_url" {
  description = "Cloud Run service URL"
  value       = google_cloud_run_v2_service.main.uri
}

output "dashboard_url" {
  description = "Dashboard URL"
  value       = "${google_cloud_run_v2_service.main.uri}/frontend/index.html"
}

output "artifact_registry" {
  description = "Artifact Registry URL"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${var.app_name}"
}

output "db_connection_name" {
  description = "Cloud SQL connection name"
  value       = google_sql_database_instance.main.connection_name
}

