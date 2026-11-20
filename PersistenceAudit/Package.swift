// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "PersistenceAudit",
    platforms: [
        .macOS(.v13)
    ],
    targets: [
        .executableTarget(
            name: "PersistenceAudit",
            path: "Sources/PersistenceAudit",
            swiftSettings: [
                .unsafeFlags(["-parse-as-library"])
            ]
        )
    ]
)
