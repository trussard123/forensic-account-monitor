import Foundation

// ============================================================
// SetupWizard.swift
// FORENSIC MONITOR v4.0.0
// Copyright (c) 2026 Thomas D. Kraemer / Kraemer Inc.
// All Rights Reserved.
// ============================================================
// First-run setup wizard.
// Checks all required dependencies and configuration.
// Guides user through setup before monitor starts.
// ============================================================

final class SetupWizard {

    static let shared = SetupWizard()

    private let home = FileManager.default.homeDirectoryForCurrentUser
    private var configPath: String {
        home.appendingPathComponent(".forensic_monitor_config").path
    }

    private init() {}

    // ── Run setup check — returns true if ready to start ─────
    func runIfNeeded() -> Bool {
        print("\n[SetupWizard] Checking configuration...\n")

        var allGood = true

        allGood = checkLogDirectory()    && allGood
        allGood = checkConfig()          && allGood
        allGood = checkCoreLocation()    && allGood
        allGood = checkFullDiskAccess()  && allGood

        if allGood {
            print("\n[SetupWizard] ✓ All checks passed. Starting Forensic Monitor.\n")
        } else {
            print("\n[SetupWizard] ✗ Setup incomplete. Resolve the above issues and restart.\n")
        }

        return allGood
    }

    // ── Check 1 — Log directory ───────────────────────────────
    private func checkLogDirectory() -> Bool {
        let logDir = home.appendingPathComponent("Documents/forensic_monitor")
        if !FileManager.default.fileExists(atPath: logDir.path) {
            try? FileManager.default.createDirectory(at: logDir,
                withIntermediateDirectories: true)
            print("[SetupWizard] ✓ Created log directory: \(logDir.path)")
        } else {
            print("[SetupWizard] ✓ Log directory exists: \(logDir.path)")
        }
        return true
    }

    // ── Check 2 — Config file ─────────────────────────────────
    private func checkConfig() -> Bool {
        guard FileManager.default.fileExists(atPath: configPath) else {
            print("[SetupWizard] ✗ Config file not found at ~/.forensic_monitor_config")
            print("              Create it with:")
            print("              PUSHOVER_TOKEN=\"your_token\"")
            print("              PUSHOVER_USER=\"your_user_key\"")
            print("              GMAIL_USER=\"your@gmail.com\"")
            print("              GMAIL_PASS=\"your_app_password\"")
            print("              GMAIL_TO=\"your@gmail.com\"")
            print("              GITHUB_TOKEN=\"your_github_token\"")
            print("              GITHUB_REPO=\"username/repo\"")
            return false
        }

        // Verify required keys are present
        guard let contents = try? String(contentsOfFile: configPath, encoding: .utf8) else {
            print("[SetupWizard] ✗ Cannot read config file")
            return false
        }

        let required = ["PUSHOVER_TOKEN", "PUSHOVER_USER", "GMAIL_USER", "GMAIL_PASS", "GMAIL_TO"]
        var missing: [String] = []
        for key in required {
            if !contents.contains(key) { missing.append(key) }
        }

        if missing.isEmpty {
            print("[SetupWizard] ✓ Config file valid")
            return true
        } else {
            print("[SetupWizard] ✗ Config missing keys: \(missing.joined(separator: ", "))")
            return false
        }
    }

    // ── Check 3 — CoreLocationCLI ─────────────────────────────
    private func checkCoreLocation() -> Bool {
        let paths = [
            "/usr/local/bin/CoreLocationCLI",
            "/opt/homebrew/bin/CoreLocationCLI"
        ]
        for path in paths {
            if FileManager.default.fileExists(atPath: path) {
                print("[SetupWizard] ✓ CoreLocationCLI found at \(path)")
                return true
            }
        }
        print("[SetupWizard] ✗ CoreLocationCLI not found")
        print("              Install with: brew install corelocationcli")
        return false
    }

    // ── Check 4 — Full Disk Access hint ──────────────────────
    private func checkFullDiskAccess() -> Bool {
        // Attempt to read a protected log path as a proxy check
        let testPath = "/var/log/system.log"
        if FileManager.default.isReadableFile(atPath: testPath) {
            print("[SetupWizard] ✓ Full Disk Access appears granted")
            return true
        } else {
            print("[SetupWizard] ⚠ Full Disk Access may not be granted")
            print("              Go to: System Settings > Privacy & Security > Full Disk Access")
            print("              Add Terminal (or this app) to the list")
            // Non-fatal — log stream may still work
            return true
        }
    }
}
