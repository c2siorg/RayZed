terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "3.90.0"
    }
  }
}

provider "google" {
  credentials = file("keys/service_account.json")
  project     = var.project
}

# #########################################################################################################################################
#                                                            Resources
# #########################################################################################################################################
resource "google_compute_firewall" "rules" {
  project     = var.project
  name        = "ray-cluster"
  network     = "default"
  description = "Create firewall rules"

  allow {
    protocol = "tcp"
    ports    = ["6379", "8265", "10001"]
  }

  allow {
    protocol = "udp"
    ports    = ["6379", "8265", "10001"]
  }

  target_tags   = ["ray-port", "ray-dashboard", "ray-client-server"]
  source_ranges = ["0.0.0.0/0"]
}

/* resource "google_compute_subnetwork" "default" {
  name          = "ray-subnet"
  ip_cidr_range = var.subnet
  region        = var.region
  network       = "default"
}

resource "google_compute_address" "head-internal-ip" {
  name         = "head-internal-address"
  subnetwork   = google_compute_subnetwork.default.id
  address_type = "INTERNAL"
  address      = var.head_ip
  region       = var.region
} */

resource "google_compute_instance" "vm_instance" {
  for_each = var.vm_nodes

  project = var.project

  name = each.value.vm_name

  machine_type = var.machine_type

  zone = var.zone

  boot_disk {
    initialize_params {
      image = var.image
      size  = var.disk_size
      type  = "pd-standard"
    }
  }

  network_interface {
    network = "default"
    /* subnetwork = "default"
    network_ip = each.value.vm_type == "head" ? var.head_ip : null */
    access_config {
    }
  }

  metadata = {
    ssh-keys = "${var.ssh_user}:${file(var.ssh_pub_key)}"
  }

  tags = each.value.vm_type == "head" ? ["externalssh", "http-server", "https-server", "ray-port", "ray-dashboard", "ray-client-server"] : ["externalssh"]

  provisioner "remote-exec" {
    inline = ["sudo apt update"]

    connection {
      type = "ssh"

      port = 22

      user = var.ssh_user

      host = self.network_interface[0].access_config[0].nat_ip

      private_key = file(var.ssh_prv_key)

      timeout = "5m"
    }
  }

  provisioner "local-exec" {
    command = "ansible-playbook --extra-vars='{\"ssh_user\" : ${var.ssh_user},\"project\" : ${var.project},\"vm_type\" : ${each.value.vm_type},\"ray_file\" : ${var.ray_file},\"scan_file\" : ${var.scan_file},\"service_file\" : ${var.service_file},\"service_account_file\" : ${var.service_account_file},\"head_ip\" : ${google_compute_instance.vm_instance["head"].network_interface[0].network_ip},\"ray_port\" : ${var.ray_port},\"ray_passwd\" : ${var.ray_passwd}}' -i '${self.network_interface[0].access_config[0].nat_ip},' playbook.yaml"
  }

  #provisioner "remote-exec" {
  #  inline = each.value.vm_type == "head" ? ["ray stop", "sudo ray start --head --port=${var.ray_port} --include-dashboard=true"] : ["ray stop", "sudo ray start --address=${google_compute_instance.vm_instance["head"].network_interface[0].network_ip}:${var.ray_port} --redis-password=${var.ray_passwd}"]
  #
  #  connection {
  #    type = "ssh"
  #
  #    port = 22
  #
  #    user = var.ssh_user
  #
  #    host = self.network_interface[0].access_config[0].nat_ip
  #
  #    private_key = file(var.ssh_prv_key)
  #
  #    timeout = "5m"
  #  }
  #}

}
