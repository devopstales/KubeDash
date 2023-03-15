class KubectlLogin < Formula
  desc "An application that can be used to easily enable authentication flows via OIDC for a kubernetes cluster. "
  homepage "https://github.com/devopstales/kube-openid-connect/"
  license "Apache-2.0"
  version "1.1"

  if OS.mac?
    url "https://github.com/devopstales/kube-openid-connect/releases/download/client_v1.1/kubectl-login_osx.tar.gz"
    sha256 "5632a3a390eac6c3de3b8602fd61286f1c808a73860201a75dd4ea71d5a88d1b"
  elsif OS.linux?
    url "https://github.com/devopstales/kube-openid-connect/releases/download/client_v1.1/kubectl-login_linux.tar.gz"
    sha256 "9ff65972af7d5ef46b642dd778145f460875426c8d253ecd2906b457b7e81559"
  end

  def install
    bin.install "kubectl-login"
  end

  test do
    system "kubectl-login test"
  end
end