module "vpc" {
    source = "terraform-aws-modules/vpc/aws"
    cidr = "${aws_vpc_cidr}"
    azs = "${aws_vpc_azs}"
    private_subnets = "${aws_vpc_private_subnets}"
    public_subnets = "${aws_vpc_public_subnets}"
}
