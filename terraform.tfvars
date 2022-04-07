# #########################################################################################################################################
#                                                           Terraform Variables
# #########################################################################################################################################

project = "terraform-project-339305"

vm_nodes = {
  head     : { vm_type : "head", vm_name : "rayzed-instance-head" }
  worker_1 : { vm_type : "worker", vm_name : "rayzed-instance-worker-01" }
  worker_2 : { vm_type : "worker", vm_name : "rayzed-instance-worker-02" }
  worker_3 : { vm_type : "worker", vm_name : "rayzed-instance-worker-03" }
}

machine_type = "e2-standard-2"

region = "us-east1"

zone = "us-east1-b"

image = "ubuntu-1804-lts"

ssh_user = "tmdan478"

ssh_prv_key = "/home/aroshd/.ssh/tmdan478_key"

ssh_pub_key = "/home/aroshd/.ssh/tmdan478_key.pub"

# #########################################################################################################################################
#                                                            Ansible Variables
# #########################################################################################################################################

ray_file = "queue-master.py"

scan_file = "Scan.py"

service_file = "zedzap.service"

service_account_file = "service_account.json"

ray_passwd = "5241590000000000"

ray_port = "6379"
