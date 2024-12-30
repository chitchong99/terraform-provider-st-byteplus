terraform {
  required_providers {
    st-byteplus = {
      source = "example.local/myklst/st-byteplus"
    }
  }
}

provider "st-byteplus" {
  region     = "ap-singapore-1"
  access_key = "NOT_USED"
  secret_key = "NOT_USED"
}

data "st-byteplus_cdn_domain" "example" {
  domain_name = "www.example.com"

  client_config {
    access_key = ""
    secret_key = ""
  }
}

output "cdn_domain_details" {
  value = data.st-byteplus_cdn_domain.example
}
