
# Docker Registry Integration

## Using CORS

Your server should be configured to accept CORS.

If your docker registry does not need credentials, you will need to send this HEADER:

```yaml
Access-Control-Allow-Origin: ['*']
```

If your docker registry need credentials, you will need to send these HEADERS (you must add the protocol `http`/`https` and the port when not default `80`/`443`):

```yaml
http:
  headers:
    Access-Control-Allow-Origin: ['http://registry.example.com']
    Access-Control-Allow-Credentials: [true]
    Access-Control-Allow-Headers: ['Authorization', 'Accept', 'Cache-Control']
    Access-Control-Allow-Methods: ['HEAD', 'GET', 'OPTIONS'] # Optional
```

## Enable delete

For deleting images, you need to activate the delete feature in the UI with `DELETE_IMAGES=true` and in your registry:

```yaml
storage:
    delete:
      enabled: true
```

And you need to add these HEADERS:

```yaml
http:
  headers:
    Access-Control-Allow-Methods: ['HEAD', 'GET', 'OPTIONS', 'DELETE']
    Access-Control-Allow-Headers: ['Authorization', 'Accept', 'Cache-Control']
    Access-Control-Expose-Headers: ['Docker-Content-Digest']
```

## Baic Authentication

```yaml
auth:
  htpasswd:
    realm: basic-realm
    path: /etc/docker/registry/htpasswd
```

