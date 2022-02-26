variable "project" {
  type    = string
  default = ""
}

variable "vm_nodes" {
  type    = map(any)
  default = {}
}

variable "machine_type" {
  type    = string
  default = ""
}

variable "region" {
  type  = string
  default = ""
}

variable "zone" {
  type    = string
  default = ""
}

variable "image" {
  type = string
  default = "debian-cloud/debian-10"
}

variable "disk_size" {
  type = number
  default = 10
}

variable "ssh_user" {
  type    = string
  default = ""
}

variable "ssh_pub_key" {
  type    = string
  default = ""
}

variable "ssh_prv_key" {
  type    = string
  default = ""
}

variable "nfs" {
  type    = string
  default = ""
}

variable "ray_file" {
  type    = string
  default = "queue-master.py"
}

variable "scan_file" {
  type    = string
  default = "Scan.py"
}

variable "service_file" {
  type    = string
  default = "zedzap.service"
}

variable "ray_passwd" {
  type = string
  default = "5241590000000000"
}

variable "ray_port" {
  type = string
  default = "6379"
}

variable "service_account_file" {
  type    = string
  default = "service_account.json"
}
