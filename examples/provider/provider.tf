terraform {
  required_providers {
    st-byteplus = {
      source = "example.local/myklst/st-byteplus"
    }
  }
}

provider "st-byteplus" {
  region = "cn-hongkong"
}

resource "st-byteplus_iam_policy" "name" {

}
