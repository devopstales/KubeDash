# User Management

KubeDash use OICD as its main [authentication mechanism](authentication.md) but from KubeDash 2.0 you can create local users from the UI and convert them into Kubernetes users. With this solution Kubernetes will use certificate based authentication. The benefit of this approach date you can authenticate without a working OICD Identity Provider so it is perfect for admin users.

