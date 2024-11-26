## First Log In

To log in for the first time the default user and password is `admin` `admin`. After you log into the web-ui you will alert to change the default admin password.

![First Login](../img/KubeDash_1.0_pic_03.png)

## Authentication

One of the key features that KubeDash adds to Kubernetes is centralized user management. This feature allows to set up local users and/or connect to an external OIDC authentication provider. By connecting to an external authentication provider, you can leverage that provider's user and groups.

### Reset Admin Password

You can reset the admin password of the application from commandline:

```bash
kubectl exec -it kubedash-bd959b784-ldd4t bash
$ flask cli reset-password
New password for default administrator (admin): admin
admin
User Updated Successfully
```

![First Login](../img/KubeDash_1.1_pic_02_login.png)
### Configure OIDC provider

To add an OIDC provider to KubeDash go to `Settings > SSO Configuration`:

| Parameter | Description |
|-----------|-------------|
| Redirect URI | `https://yourKubDashHostURL` |
| Identity Provider URL | The URL of your IdP. |
| Identity Provider Client ID | The `Client ID` of your IdP client. |
| Identity Provider Client Secret | The generated `Secret` of your IdP client.  |

![Configure OIDC provider](../img/KubeDash_1.0_pic_07_sso_config.png)

## Authorization

Once an user logged in to KubeDash the their access rights within the system, is determined by the user's role. There i two role in KubeDash User and Admin. This role determinate what you can configure in KubeDash. 

## Role-Based Access Control (RBAC)

From kubernetes perspective all of your privileges are determined by Role-Based Access Control (RBAC). The KubeDash Admin role allow you to use the KubeDash pod's cluster-admin ServiceAccount for the interactions with the kubernetes API. 

With the Local role KubeDash use your OIDC token for the same purpose, so you have the same privileges as in the cli.
