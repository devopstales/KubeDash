# Kubectl Plugin

Kubectl has the ability to extend it's functionality with plugins. To ease the download and installation of the kubectl config KubeDash offers a simple kubectl plugin for login. I will open the login page automatically in the browser and merge the configuration to the local kubectl config.

## Install Kubectl plugin

```bash
# Homebrew (macOS and Linux)
brew tap devopstales/devopstales
brew install kubectl-kdlogin

# My krew repo (macOS, Linux, Windows and ARM)
kubectl krew index add devopstales https://github.com/devopstales/krew
kubectl krew install devopstales/kdlogin

# Chocolatey (Windows)
choco install kubectl-kdlogin

# Binary release (Windows, macOS and Linux)
https://github.com/devopstales/kubedash/releases
```

## Use the plugin

```bash
$ kubectl kdlogin /
Configfile created with config for productioncluster to ~/.kube/config
Happy Kubernetes interaction!
```
