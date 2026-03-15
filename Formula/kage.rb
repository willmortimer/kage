class Kage < Formula
  desc "Hardware-backed age plugin for team secrets"
  homepage "https://github.com/willmortimer/kage"

  # NOTE: This formula is intended to be updated per release.
  # The release workflow publishes versioned archives and writes SHA256SUMS files.
  # Update `version` + `sha256` from the GitHub Release assets.
  version "0.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/willmortimer/kage/releases/download/v#{version}/kage-#{version}-macos-arm64.tar.gz"
      sha256 "REPLACE_WITH_SHA256"
    else
      odie "kage macOS packages are Apple silicon only"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      odie "kage Linux arm64 bottles are not published yet"
    else
      url "https://github.com/willmortimer/kage/releases/download/v#{version}/kage-#{version}-linux-x86_64.tar.gz"
      sha256 "REPLACE_WITH_SHA256"
    end
  end

  def install
    if OS.mac? && MacOS.version.to_i < 26
      odie "kage requires macOS 26+"
    end
    bin.install "kage"
    bin.install "kaged"
    bin.install "age-plugin-kage"
  end

  def caveats
    <<~EOS
      SOPS integration:
        export SOPS_AGE_KEY_CMD="kage identity"

      macOS helper:
        Install the GUI/XPC daemon with:
          brew install --cask kage-helper
    EOS
  end

  test do
    assert_match "kage", shell_output("#{bin}/kage --help")
  end
end
