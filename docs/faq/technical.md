# Technical

## How can I reset the administrator password?

Kubernetes install (Helm):

```bash
$ kubectl -n kubedash exec $(kubectl -n kubedash get pods -l app=kubedash | grep '1/1' | head -1 | awk '{ print $1 }') -- flask commands reset-password
New password for default administrator (admin):
<new_password>
```

## How can I enable debug logging?