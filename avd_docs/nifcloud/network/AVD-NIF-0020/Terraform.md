
Use a more recent TLS/SSL policy for the load balancer

```hcl
 resource "nifcloud_load_balancer" "good_example" {
    policy_type         = "standard"
    ssl_policy_name     = "Standard Ciphers D ver1"
    load_balancer_port  = "HTTPS"
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/load_balancer#ssl_policy_name

 - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/load_balancer_listener#ssl_policy_name

