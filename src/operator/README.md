# KubeDash Operator

## CRDs

* User - Cluster
* Groupe - Cluster
* Project - Cluster

```bash
$ oc get user

NAME      UID                                    FULL NAME   IDENTITIES
demo     75e4b80c-dbf1-11e5-8dc6-0e81e52cc949               htpasswd_auth:demo

$ oc get identity

NAME                  IDP NAME        IDP USER NAME   USER NAME   USER UID
htpasswd_auth:demo    htpasswd_auth   demo            demo        75e4b80c-dbf1-11e5-8dc6-0e81e52cc949

# oc get groups

NAME      USERS
west      john, betty
```

```bash
KIND:     User
VERSION:  user.openshift.io/v1

DESCRIPTION:
     User is an object that represents an OpenShift user

FIELDS:
   apiVersion   <string>
   identities   <[]string>
   kind         <string>
   metadata     <Object>
   fullName     <string>
   groups       <[]string>
```

```bash
KIND:     Group
VERSION:  user.openshift.io/v1

DESCRIPTION:
     Group is a collection of users.

FIELDS:
   apiVersion   <string>
   kind         <string>
   metadata     <Object>
   users        <[]string>
```

```bash
KIND:     Identity
VERSION:  user.openshift.io/v1

DESCRIPTION:
     Identity is an immutable record that represents a single successful act of authentication
     by a user. Some identities may be long-lived (like for an LDAP user), others short-lived
     (like a GitHub OAuth token).

FIELDS:
   apiVersion           <string>
   extra                <map[string]string>
   kind                 <string>
   metadata             <Object>
   providerName         <string>
   providerUserName     <string>
   user                 <Object>
```

```bash
KIND:     Project
VERSION:  project.openshift.io/v1

DESCRIPTION:
     Project is a logical top-level container for a set of OpenShift resources.

FIELDS:
   apiVersion   <string>
   kind         <string>
   metadata     <Object>
   spec         <Object>
     finalizers   <[]string>
   status       <Object>
     phase        <string>
```

The pod will liste on port 8443 and 443. The 8443 is the external api and the 443 is the kopf based operator.

It will create a `APIService` object for the api server to connect to port `8443`.
It will create a `ValidatingWebhookConfiguration` to connet to port `443`.

The admission Controller functionality:

| Trigger                | Action                           |
| ---------------------- | -------------------------------- |
| `Project` is created   | Create corresponding `Namespace` |
| `Namespace` is created | Create corresponding `Project`   |
| `Namespace` is deleted | Delete corresponding `Project`   |
| `Project` is deleted   | Delete corresponding `Namespace` |
