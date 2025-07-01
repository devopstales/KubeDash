# Project Data

Project specific information can be stored in the namespace level that the Dashboard will visualize.

| Annotation | Description |
| ---------- | ----------- |
| `metadata.k8s.io/owner` | username |
| `metadata.k8s.io/description` | Unstructured text description of the service for humans. |
| `metadata.k8s.io/chat` | Slack channel (prefix with #), or link to other external chat system. |
| `metadata.k8s.io/bugs` | Link to external bug tracker. |
| `metadata.k8s.io/documentation` | Link to external project documentation. |
| `metadata.k8s.io/repository` | Link to external VCS repository. |
| `metadata.k8s.io/pipeline` | Link to external CI/CD. |
| `metadata.k8s.io/egress-ip` | ehgress ip if ns specific |
| `metadata.k8s.io/ingress-ip` | ingress ip if ns specific |

Based on Example: https://ambassadorlabs.github.io/k8s-for-humans/
