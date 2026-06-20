import Foundation

// ============================================================
// AlertManager.swift
// FORENSIC MONITOR v4.0.0
// Copyright (c) 2026 Thomas D. Kraemer / Kraemer Inc.
// All Rights Reserved.
// ============================================================

final class AlertManager {

    static let shared = AlertManager()

    var pushoverToken: String = ""
    var pushoverUser: String = ""
    var gmailUser: String = ""
    var gmailPass: String = ""
    var gmailTo: String = ""
    var testMode: Bool = false // Set to true to disable actual Pushover sends

    private init() {
        loadConfig()
    }

    private func loadConfig() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let configPath = home.appendingPathComponent(".forensic_monitor_config").path
        guard let contents = try? String(contentsOfFile: configPath, encoding: .utf8) else {
            print("[AlertManager] Config file not found")
            return
        }
        for line in contents.components(separatedBy: .newlines) {
            let parts = line.components(separatedBy: "=")
            guard parts.count == 2 else { continue }
            let key = parts[0].trimmingCharacters(in: .whitespaces)
            let value = parts[1].trimmingCharacters(in: .whitespaces)
                .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            switch key {
            case "PUSHOVER_TOKEN": pushoverToken = value
            case "PUSHOVER_USER":  pushoverUser  = value
            case "GMAIL_USER":     gmailUser     = value
            case "GMAIL_PASS":     gmailPass     = value
            case "GMAIL_TO":       gmailTo       = value
            default: break
            }
        }
    }

    func pushover(title: String, message: String, priority: Int = 0) {
        guard !pushoverToken.isEmpty, !pushoverUser.isEmpty else { return }
        
        let timestamp = ISO8601DateFormatter().string(from: Date())
        
        // TEST MODE: Log without actually sending
        if testMode {
            let logLine = "\(timestamp) | [TEST MODE] priority=\(priority) | status=SIMULATED | title=\(title) | \(message)\n"
            print("[AlertManager] TEST MODE - Would send Pushover: \(title) | \(message)")
            appendToDeliveryLog(logLine)
            return
        }
        
        // PRODUCTION: Actually send to Pushover
        guard let url = URL(string: "https://api.pushover.net/1/messages.json") else { return }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded",
                         forHTTPHeaderField: "Content-Type")

        let encoded = title.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? title
        let msgEncoded = message.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? message
        let bodyString = "token=\(pushoverToken)&user=\(pushoverUser)&title=\(encoded)&message=\(msgEncoded)&priority=\(priority)"
        request.httpBody = bodyString.data(using: String.Encoding.utf8)

        URLSession.shared.dataTask(with: request) { _, response, error in
            if let error = error {
                print("[AlertManager] Pushover error: \(error.localizedDescription)")
                return
            }
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            let logLine = "\(timestamp) | priority=\(priority) | status=\(status) | title=\(title) | \(message)\n"
            self.appendToDeliveryLog(logLine)
        }.resume()
    }

    func gmail(subject: String, htmlBody: String) {
        guard !gmailUser.isEmpty, !gmailPass.isEmpty, !gmailTo.isEmpty else { return }

        let header = "<div style=\"font-family:monospace;font-size:18px;font-weight:700;color:#00ff88;letter-spacing:.08em;margin-bottom:24px;\">FORENSIC_MONITOR</div>"
        let fullHTML = "<html><body style=\"font-family:monospace;font-size:13px;line-height:1.6;color:#111;max-width:720px;padding:24px;\">\(header)\(htmlBody)</body></html>"

        let emailContent = "From: Forensic Monitor <\(gmailUser)>\nTo: \(gmailTo)\nSubject: \(subject)\nMIME-Version: 1.0\nContent-Type: text/html; charset=UTF-8\n\n\(fullHTML)"

        let tmpFile = FileManager.default.temporaryDirectory
            .appendingPathComponent("fm_email_\(Date().timeIntervalSince1970).tmp")
        try? emailContent.write(to: tmpFile, atomically: true, encoding: .utf8)

        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        task.arguments = [
            "-s",
            "--url", "smtps://smtp.gmail.com:465",
            "--ssl-reqd",
            "--user", "\(gmailUser):\(gmailPass)",
            "--mail-from", gmailUser,
            "--mail-rcpt", gmailTo,
            "--upload-file", tmpFile.path
        ]
        try? task.run()
        task.waitUntilExit()
        try? FileManager.default.removeItem(at: tmpFile)
    }

    private func appendToDeliveryLog(_ line: String) {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let logPath = home
            .appendingPathComponent("Documents/forensic_monitor/PUSHOVER_DELIVERY.log")
        if let handle = try? FileHandle(forWritingTo: logPath) {
            handle.seekToEndOfFile()
            if let data = line.data(using: String.Encoding.utf8) {
                handle.write(data)
            }
            handle.closeFile()
        }
    }
}
