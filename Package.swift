// swift-tools-version: 5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Zsign",
	platforms: [
		.iOS(.v12),
		.macOS(.v10_15),
		.tvOS(.v12),
		.watchOS(.v8),
		.custom("xros", versionString: "1.3")
	],
	products: [
		.library(
			name: "zsignc",
			targets: ["ZsignC"]
		),
		.library(
			name: "Zsign",
			targets: ["Zsign"]
		),
	],
	dependencies: [
		.package(url: "https://github.com/krzyzanowskim/OpenSSL", from: "3.3.3001")
	],
	targets: [
		.target(
			name: "ZsignC",
			dependencies: [
				.product(name: "OpenSSL", package: "OpenSSL")
			],
			path: ".",
			exclude: [
				"src/common/archive.cpp",
				"src/zsign.cpp"
			],
			sources: [
				"src/archo.cpp",
				"src/bundle.cpp",
				"src/macho.cpp",
				"src/openssl.cpp",
				"swift/utils.mm",
				"src/signing.cpp",
				"swift/zsign.mm",
				"src/common/base64.cpp",
				"src/common/fs.cpp",
				"src/common/json.cpp",
				"src/common/log.cpp",
				"src/common/sha.cpp",
				"src/common/timer.cpp",
				"src/common/util.cpp"
			],
			publicHeadersPath: "src/include",
			cxxSettings: [
				.headerSearchPath("src"),
				.headerSearchPath("src/common"),
				.unsafeFlags(["-std=c++17"])
			],
			linkerSettings: [
				.linkedFramework("OpenSSL"),
			]
		),
		.target(
			name: "Zsign",
			dependencies: [
				"ZsignC"
			],
			path: "swift",
			sources: [
				"zsign.swift"
			]
		)
	]
)
