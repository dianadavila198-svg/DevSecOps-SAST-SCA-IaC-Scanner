# ---------------------------------------------------------------------------
# DEMONSTRATION FILE — IaC Scanning Pillar
# ---------------------------------------------------------------------------
# UoA Sense Map does not currently provision infrastructure via Terraform
# (deployment is Gunicorn + Whitenoise, no cloud IaC in place). This file
# exists only to prove the checkov (Terraform) integration works end-to-end,
# using True Positives (TP) and True Negatives (TN) 
#
# This file only works as infraestructure sample. It is scanned
# by CI to demonstrate the IaC pillar with genuine findings.
# ---------------------------------------------------------------------------

# --- TP: security group open to the entire internet on a DB port ---
# 0.0.0.0/0 = wildcard for EVERY IP address on the internet. Combined
# with port 5432 (Postgres), this lets anyone, anywhere, attempt to
# connect directly to the database — bypassing the app layer and auth
# entirely. Same "wildcard = trust nobody" risk as ALLOWED_HOSTS=['*']
# and open SSRF targets from the SAST pillar.
resource "aws_security_group" "demo_db_sg" {
  name        = "demo-db-security-group"
  description = "DEMO ONLY — intentionally misconfigured for IaC scan demonstration"

  ingress {
    description = "Postgres — INTENTIONALLY open to 0.0.0.0/0 (TP finding)"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Outbound traffic — less risky by default, included for structural
  # completeness. checkov's actual flagged finding is the ingress rule above.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- TN: same shape, correctly scoped to a specific IP range ---
# A specific range of IP addresses (256 addresses) instead of a wildcard — only
# known, trusted sources can even attempt a connection.
resource "aws_security_group" "demo_db_sg_safe" {
  name        = "demo-db-security-group-safe"
  description = "DEMO ONLY — correctly scoped security group (TN comparison)"

  ingress {
    description = "Postgres — restricted to a specific trusted IP range"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"] #/24 covers every address from 203.0.113.0 to 203.0.113.255 — 256 addresses total
  }
}

# --- TP: database instance with no encryption at rest ---
# storage_encrypted = false means data sitting on disk is stored in
# plaintext. If the underlying storage is ever improperly accessed
# (backup leak, misconfigured snapshot, physical access), the data is
# immediately readable — no extra step needed. Also hardcodes a real
# secret directly in source, same root problem as SEC-MISCONFIG-
# HARDCODED-SECRET from the SAST pillar.
resource "aws_db_instance" "demo_db" {
  identifier        = "demo-sensemap-db"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_encrypted = false   # INTENTIONAL — missing encryption at rest (TP finding)
  username = "demo_admin"
  password = "demo-insecure-password-123"   # INTENTIONAL — hardcoded secret (TP finding)
  skip_final_snapshot = true
}

# --- TN: same resource shape, correctly configured ---
# Encryption enabled, and the password is sourced from a variable
# (supplied via environment/CI secret at apply-time) instead of being
# written directly into the file.
resource "aws_db_instance" "demo_db_safe" {
  identifier        = "demo-sensemap-db-safe"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_encrypted = true
  username = "demo_admin"
  password = var.db_password
  skip_final_snapshot = true
}

variable "db_password" {
  description = "Database password, supplied via environment/CI secret — never hardcoded"
  type        = string
  sensitive   = true
}

# --- TP: IAM policy with unrestricted permissions ---
# Action = "*" means EVERY possible AWS action (create, delete, read,
# modify — literally anything). Resource = "*" means it applies to
# EVERY resource in the whole AWS account, not just this project's.
# A different LAYER of security than the two examples above: those
# controlled WHO CAN REACH a resource (network) and WHETHER DATA IS
# READABLE (encryption); this controls WHAT AN IDENTITY IS ALLOWED TO
# DO once it's already authenticated. If this role's credentials are
# ever leaked (e.g. via the SSRF metadata-endpoint attack from the
# SAST pillar), the attacker inherits full control of the AWS account,
# not just this one app.
resource "aws_iam_policy" "demo_app_policy" {
  name        = "demo-sensemap-app-policy"
  description = "DEMO ONLY — intentionally overly permissive (TP finding)"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# --- TN: same policy shape, scoped to least privilege ---
# Only the specific actions this app actually needs (reading/writing
# objects in ITS OWN storage bucket), and only against that one named
# resource — not the whole AWS account. Even if these credentials
# leak, the blast radius is limited to this one bucket, nothing else.
resource "aws_iam_policy" "demo_app_policy_safe" {
  name        = "demo-sensemap-app-policy-safe"
  description = "DEMO ONLY — least-privilege scoped policy (TN comparison)"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::demo-sensemap-uploads/*"
      }
    ]
  })
}