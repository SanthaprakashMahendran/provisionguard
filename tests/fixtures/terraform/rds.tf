resource "aws_db_subnet_group" "main" {
  name       = "${var.project}-db"
  subnet_ids = aws_subnet.private[*].id

  tags = merge(local.common_tags, { Name = "${var.project}-db-subnets" })
}

resource "aws_db_instance" "main" {
  identifier     = "${var.project}-db"
  engine         = "postgres"
  engine_version = "16"
  instance_class = "db.m5.large"

  allocated_storage = 100
  storage_type      = "gp3"
  storage_encrypted = false

  db_name                     = "appdb"
  username                    = "appadmin"
  manage_master_user_password = true

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  multi_az               = false
  publicly_accessible    = false

  deletion_protection = false
  skip_final_snapshot = true

  tags = {
    Name        = "${var.project}-db"
    environment = "dev"
    owner       = "platform-team"
  }
}
