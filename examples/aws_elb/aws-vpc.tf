module "vpc" {
    source = "terraform-aws-modules/vpc/aws"
    cidr = "10.0.0.0/16"
    azs = ["us-east-1a", "us-east-1c"]
    private_subnets = ["10.0.12.0/24", "10.0.24.0/24"]
    public_subnets = ["10.0.36.0/24", "10.0.48.0/24"]
}
