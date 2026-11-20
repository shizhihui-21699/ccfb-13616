import Foundation

// MARK: - String 路径便捷方法（新 SDK 已移除 String 上的 NSString 路径 API，这里补回）
extension String {
    var lastPathComponent: String {
        (self as NSString).lastPathComponent
    }

    var deletingLastPathComponent: String {
        (self as NSString).deletingLastPathComponent
    }

    var pathExtension: String {
        (self as NSString).pathExtension
    }
}
