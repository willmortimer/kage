cask "kage-helper" do
  version "0.0.0"
  sha256 "REPLACE_WITH_SHA256"

  url "https://github.com/willmortimer/kage/releases/download/v#{version}/kagehelper-#{version}-macos-arm64.zip"
  name "Kage Helper"
  desc "Kage macOS menu bar helper app exposing the com.kage.daemon XPC service"
  homepage "https://github.com/willmortimer/kage"

  depends_on macos: ">= :tahoe"
  depends_on arch: :arm64

  app "KageHelper.app"

  artifact "com.kage.daemon.plist", target: "#{Dir.home}/Library/LaunchAgents/com.kage.daemon.plist"

  postflight do
    agent_plist = "#{Dir.home}/Library/LaunchAgents/com.kage.daemon.plist"
    system_command "/bin/launchctl",
                   args: ["bootout", "gui/#{Process.uid}/com.kage.daemon"],
                   sudo: false,
                   must_succeed: false
    system_command "/bin/launchctl",
                   args: ["bootout", "gui/#{Process.uid}", agent_plist],
                   sudo: false,
                   must_succeed: false
    system_command "/bin/launchctl",
                   args: ["bootstrap", "gui/#{Process.uid}", agent_plist],
                   sudo: false
    system_command "/bin/launchctl",
                   args: ["kickstart", "-k", "gui/#{Process.uid}/com.kage.daemon"],
                   sudo: false,
                   must_succeed: false
  end

  uninstall do
    agent_plist = "#{Dir.home}/Library/LaunchAgents/com.kage.daemon.plist"
    system_command "/bin/launchctl",
                   args: ["bootout", "gui/#{Process.uid}/com.kage.daemon"],
                   sudo: false,
                   must_succeed: false
    system_command "/bin/launchctl",
                   args: ["bootout", "gui/#{Process.uid}", agent_plist],
                   sudo: false,
                   must_succeed: false
  end

  caveats <<~EOS
    KageHelper installs a per-user LaunchAgent (com.kage.daemon).

    If it fails to load, run these recovery commands from Terminal.app:

      launchctl bootout gui/$UID ~/Library/LaunchAgents/com.kage.daemon.plist || true
      launchctl bootstrap gui/$UID ~/Library/LaunchAgents/com.kage.daemon.plist
      launchctl kickstart -k gui/$UID/com.kage.daemon
      launchctl print gui/$UID/com.kage.daemon
  EOS

  zap trash: [
    "#{Dir.home}/Library/LaunchAgents/com.kage.daemon.plist",
    "#{Dir.home}/Library/Application Support/kage",
    "#{Dir.home}/.kage",
  ]
end
