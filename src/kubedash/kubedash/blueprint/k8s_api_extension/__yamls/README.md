# KubeDash Extension API Server

* https://kubernetes.io/docs/tasks/extend-kubernetes/setup-extension-api-server/
* https://kubernetes.io/docs/tasks/extend-kubernetes/configure-aggregation-layer/
* https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/apiserver-aggregation/
* https://github.com/kubernetes-sigs/metrics-server/blob/master/manifests/base/apiservice.yaml
* https://cert-manager.io/docs/concepts/ca-injector/

## K8S API Extension

* `/openapi/v2`
* `/openapi/v3`
* `/apis`
  * `APIGroupList`

```json
    {
      "name": "namespaces",
      "singularName": "namespace",
      "namespaced": false,
      "kind": "Namespace",
      "verbs": [
        "create",
        "delete",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "ns"
      ],
      "storageVersionHash": "Q3oi5N2YM8M="
    },
    {
      "name": "namespaces/finalize",
      "singularName": "",
      "namespaced": false,
      "kind": "Namespace",
      "verbs": [
        "update"
      ]
    },
    {
      "name": "namespaces/status",
      "singularName": "",
      "namespaced": false,
      "kind": "Namespace",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    },
```

## APIService

```bash
kg APIService
kubectl api-resources
```

```yaml
---
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  name: v1beta1.metrics.k8s.io
spec:
  service:
    name: metrics-server
    namespace: kube-system
  group: metrics.k8s.io
  version: v1beta1
  insecureSkipTLSVerify: true
  groupPriorityMinimum: 100
  versionPriority: 100
```

## My objects

### Project

```yaml
apiVersion: devopstales.github.io/v1
kind: Project
metadata:
  creationTimestamp: date
  name: name
  labels:
    label: value
  annotations:
    label: value
spec:
  description: "Description"
  owner: "User name"
status:
  phase: Active
```

* Status can be used to archive?
* owner vs requester
* Membership view

## Openshift

### Projects

```json
{
    "kind": "APIResourceList",
    "apiVersion": "v1",
    "groupVersion": "project.openshift.io/v1",
    "resources": [
        {
            "name": "projectrequests",
            "singularName": "",
            "namespaced": false,
            "kind": "ProjectRequest",
            "verbs": [
                "create",
                "list"
            ]
        },
        {
            "name": "projects",
            "singularName": "",
            "namespaced": false,
            "kind": "Project",
            "verbs": [
                "create",
                "delete",
                "get",
                "list",
                "patch",
                "update",
                "watch"
            ]
        }
    ]
}
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

```bash
k get projects                                           
NAME                                 DISPLAY NAME   STATUS
default                                             Active
kube-public                                         Active
kube-service-catalog                                Active
kube-system                                         Active
openshift                                           Active
openshift-ansible-service-broker                    Active
openshift-console                                   Active
openshift-cron-jobs                                 Active
openshift-infra                                     Active
openshift-logging                                   Active
openshift-metrics-server                            Active
openshift-monitoring                                Active
openshift-node                                      Active
openshift-sdn                                       Active
openshift-template-service-broker                   Active
openshift-web-console                               Active
slackbot                             slackbot       Active
```

```yaml
---
k get projects default -o yaml
apiVersion: project.openshift.io/v1
kind: Project
metadata:
  annotations:
    openshift.io/logging.data.prefix: .operations
    openshift.io/node-selector: ""
    openshift.io/sa.scc.mcs: s0:c1,c0
    openshift.io/sa.scc.supplemental-groups: 1000000000/10000
    openshift.io/sa.scc.uid-range: 1000000000/10000
  creationTimestamp: "2019-05-25T08:58:06Z"
  name: default
  resourceVersion: "22709"
  selfLink: /apis/project.openshift.io/v1/projects/default
  uid: 3639b898-7ecb-11e9-b29f-8611e6b1c395
spec:
  finalizers:
  - kubernetes
status:
  phase: Active
---
apiVersion: project.openshift.io/v1
kind: Project
metadata:
  annotations:
    openshift.io/description: 'Some description Can come here'
    openshift.io/display-name: slackbot
    openshift.io/requester: user.name@mydomain.intra
    openshift.io/sa.scc.mcs: s0:c16,c5
    openshift.io/sa.scc.supplemental-groups: 1000250000/10000
    openshift.io/sa.scc.uid-range: 1000250000/10000
  creationTimestamp: "2019-05-28T06:52:06Z"
  labels:
    router: public
  name: slackbot
  resourceVersion: "20078471"
  selfLink: /apis/project.openshift.io/v1/projects/slackbot
  uid: 1b639eb9-8115-11e9-af1a-66934f1af826
spec:
  finalizers:
  - kubernetes
status:
  phase: Active
```

The pod will listen on port 8443 and 443. The 8443 is the external api and the 443 is the kopf based operator.

It will create a `APIService` object for the api server to connect to port `8443`.
It will create a `ValidatingWebhookConfiguration` to connet to port `443`.

The admission Controller functionality:

| Trigger                | Action                           |
| ---------------------- | -------------------------------- |
| `Project` is created   | Create corresponding `Namespace` |
| `Namespace` is created | Create corresponding `Project`   |
| `Namespace` is deleted | Delete corresponding `Project`   |
| `Project` is deleted   | Delete corresponding `Namespace` |

## CRDs

* Project - Cluster
* User - Cluster
* Identity - Cluster
* Group - Cluster
* Kubeconfig - Cluster

```json
{
    "kind": "APIResourceList",
    "apiVersion": "v1",
    "groupVersion": "user.openshift.io/v1",
    "resources": [
        {
            "name": "groups",
            "singularName": "",
            "namespaced": false,
            "kind": "Group",
            "verbs": [
                "create",
                "delete",
                "deletecollection",
                "get",
                "list",
                "patch",
                "update",
                "watch"
            ]
        },
        {
            "name": "identities",
            "singularName": "",
            "namespaced": false,
            "kind": "Identity",
            "verbs": [
                "create",
                "delete",
                "deletecollection",
                "get",
                "list",
                "patch",
                "update",
                "watch"
            ]
        },
        {
            "name": "useridentitymappings",
            "singularName": "",
            "namespaced": false,
            "kind": "UserIdentityMapping",
            "verbs": [
                "create",
                "delete",
                "get",
                "patch",
                "update"
            ]
        },
        {
            "name": "users",
            "singularName": "",
            "namespaced": false,
            "kind": "User",
            "verbs": [
                "create",
                "delete",
                "deletecollection",
                "get",
                "list",
                "patch",
                "update",
                "watch"
            ]
        }
    ]
}
```

### User

```bash
oc get user

NAME      UID                                    FULL NAME   IDENTITIES
demo     75e4b80c-dbf1-11e5-8dc6-0e81e52cc949               htpasswd_auth:demo
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

OR:

```yaml
apiVersion: "apiextensions.k8s.io/v1beta1"
kind: "CustomResourceDefinition"
metadata:
  name: "permissionmanagerusers.permissionmanager.user"
spec:
  group: "permissionmanager.user"
  version: "v1alpha1"
  scope: "Cluster"
  names:
    plural: "permissionmanagerusers"
    singular: "permissionmanageruser"
    kind: "Permissionmanageruser"
  validation:
    openAPIV3Schema:
      required: ["spec"]
      properties:
        spec:
          required: ["name"]
          properties:
            name:
              type: "string"
              minimum: 2
```

```yaml
apiVersion: user.openshift.io/v1
fullName: Test User
groups: null
identities:
- shiwaforcesso:test.user@mydomain.intra
- email_jira_ldap:test.user@mydomain.intra
- sso_shiwaforce:test.user@mydomain.intra
- email_jira:test.user@mydomain.intra
kind: User
metadata:
  creationTimestamp: "2019-05-27T13:18:54Z"
  name: test.user@mydomain.intra
  resourceVersion: "7086165"
  selfLink: /apis/user.openshift.io/v1/users/test.user%40mydomain.intra
  uid: fa36d145-8081-11e9-af1a-66934f1af826
```

### Group

```bash
oc get groups

NAME      USERS
west      john, betty
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

OR:

```yml
apiVersion: redhatcop.redhat.io/v1alpha1
kind: LDAPAuthEngineGroup
metadata:
  name: ldapauthenginegroup-sample3
spec:
  authentication: 
    path: kubernetes
    role: policy-admin
    serviceAccount:
      name: default
  name: "test-3"
  path: "ldap/test"
  policies: "admin, audit, users"
```

```json
    {
      "name": "groups",
      "singularName": "group",
      "namespaced": true,
      "kind": "Group",
      "verbs": [
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "create",
        "update",
        "watch"
      ],
      "storageVersionHash": "GstsBbv2Ed8="
    },
    {
      "name": "groups/status",
      "singularName": "",
      "namespaced": true,
      "kind": "Group",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    },
```

### Identity

```bash
oc get identity

NAME                  IDP NAME        IDP USER NAME   USER NAME   USER UID
htpasswd_auth:demo    htpasswd_auth   demo            demo        75e4b80c-dbf1-11e5-8dc6-0e81e52cc949
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
