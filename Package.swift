// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SupabaseOpsGuard",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "supabase-ops-guard-helper", targets: ["SupabaseOpsGuard"]),
    ],
    targets: [
        .executableTarget(name: "SupabaseOpsGuard"),
        .testTarget(
            name: "SupabaseOpsGuardTests",
            dependencies: ["SupabaseOpsGuard"]
        ),
    ]
)
