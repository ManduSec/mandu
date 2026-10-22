# Homebrew formula for Mandu (docs/design/distribution/packaging.md §3): the same npm
# artifact as `npm install -g @mandusec/mandu` and scripts/install.sh, over
# Homebrew's own Node.
#
# TODO(first public tag): `homepage`, `url` (the release-pack tarball,
# release/mandusec-mandu-<v>.tgz on the public host) and its `sha256`
# (release/SHA256SUMS) are placeholders until the public host is chosen.
class Mandu < Formula
  desc "Keep an AI agent's secrets from its model, at the OS level"
  homepage "https://example.invalid/mandu"
  url "https://example.invalid/mandu/mandusec-mandu-0.2.0-beta.8.tgz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "Apache-2.0"

  # Mandu's floor is Node 22.13.0 (launcher/src/node-floor.ts); node@22 is past it.
  depends_on "node@22"

  def install
    system "npm", "install", *std_npm_args
    (bin/"mandu").write_env_script libexec/"bin/mandu",
      PATH: "#{Formula["node@22"].opt_bin}:$PATH"
  end

  test do
    assert_match "mandu #{version}", shell_output("#{bin}/mandu --version")
  end
end
