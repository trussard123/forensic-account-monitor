import Foundation

final class StatsPublisher {

    static let shared = StatsPublisher()

    private let home = FileManager.default.homeDirectoryForCurrentUser
    private var publishTimer: Timer?
    private let startDate = "2026-03-27"

    private var logDir: URL {
        home.appendingPathComponent("Documents/forensic_monitor")
    }
    private var statsFile: URL {
        logDir.appendingPathComponent("stats.json")
    }
    private var liveStreamFile: URL {
        logDir.appendingPathComponent("LIVE_STREAM.log")
    }

    private init() {}

    func startPublishing() {
        publishTimer = Timer.scheduledTimer(withTimeInterval: 900.0, repeats: true) { _ in
            self.publish()
        }
        publish()
    }

    func stopPublishing() {
        publishTimer?.invalidate()
        publishTimer = nil
    }

    func publish() {
        guard let contents = try? String(contentsOf: liveStreamFile, encoding: .utf8) else { return }
        let lines = contents.components(separatedBy: .newlines)
        let macPattern = "([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"
        var uniqueMACs = Set<String>()
        var latestMAC = ""
        for line in lines {
            if let range = line.range(of: macPattern, options: .regularExpression) {
                let mac = String(line[range])
                uniqueMACs.insert(mac)
                latestMAC = mac
            }
        }
        let eventCount = lines.filter { !$0.isEmpty }.count
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        let startDay = formatter.date(from: startDate) ?? Date()
        let days = Calendar.current.dateComponents([.day], from: startDay, to: Date()).day ?? 0
        fetchGitHubFloor(localCount: uniqueMACs.count) { finalCount in
            let timestamp = ISO8601DateFormatter().string(from: Date())
            let json = "{\"devices\":\(finalCount),\"days\":\(days),\"events\":\(eventCount),\"latest_mac\":\"\(latestMAC)\",\"updated\":\"\(timestamp)\"}"
            try? json.write(to: self.statsFile, atomically: true, encoding: .utf8)
            self.pushToGitHub(deviceCount: finalCount, eventCount: eventCount)
        }
    }

    private func fetchGitHubFloor(localCount: Int, completion: @escaping (Int) -> Void) {
        let config = loadGitHubConfig()
        guard let token = config.token,
              let repo = config.repo,
              let url = URL(string: "https://api.github.com/repos/\(repo)/contents/stats.json") else {
            completion(localCount)
            return
        }
        var request = URLRequest(url: url)
        request.setValue("application/vnd.github.v3.raw", forHTTPHeaderField: "Accept")
        request.setValue("token \(token)", forHTTPHeaderField: "Authorization")
        URLSession.shared.dataTask(with: request) { data, _, _ in
            guard let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let githubCount = json["devices"] as? Int else {
                completion(localCount)
                return
            }
            completion(max(localCount, githubCount))
        }.resume()
    }

    private func pushToGitHub(deviceCount: Int, eventCount: Int) {
        let scriptPath = logDir.appendingPathComponent("push_stats.sh").path
        guard FileManager.default.fileExists(atPath: scriptPath) else { return }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/bash")
        task.arguments = [scriptPath]
        try? task.run()
        task.waitUntilExit()
        let timestamp = ISO8601DateFormatter().string(from: Date())
        print("[\(timestamp)] Stats published: \(deviceCount) devices | \(eventCount) events")
    }

    private func loadGitHubConfig() -> (token: String?, repo: String?) {
        let configPath = home.appendingPathComponent(".forensic_monitor_config").path
        guard let contents = try? String(contentsOfFile: configPath, encoding: .utf8) else {
            return (nil, nil)
        }
        var token: String?
        var repo: String?
        for line in contents.components(separatedBy: .newlines) {
            let parts = line.components(separatedBy: "=")
            guard parts.count == 2 else { continue }
            let key = parts[0].trimmingCharacters(in: .whitespaces)
            let value = parts[1].trimmingCharacters(in: .whitespaces)
                .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            if key == "GITHUB_TOKEN" { token = value }
            if key == "GITHUB_REPO" { repo = value }
        }
        return (token, repo)
    }
}
