// swift-tools-version: 6.0
// The menu bar app. Built with SwiftPM so it needs no Xcode project during the POC;
// apple/build-app.sh wraps the executable into Riot.app.
import PackageDescription

let package = Package(
    name: "RiotAgent",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "RiotAgent",
            path: "Sources/RiotAgent",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "RiotAgentTests",
            dependencies: ["RiotAgent"],
            path: "Tests/RiotAgentTests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
