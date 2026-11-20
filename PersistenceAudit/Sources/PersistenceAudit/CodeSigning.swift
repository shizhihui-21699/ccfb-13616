import Foundation
import Security

// MARK: - 代码签名 / 公证 / Apple 锚点评估
// 仅对 Mach-O 与 .app 主程序调用。所有结果都是静态检查（不执行目标程序）。
struct CodeSigning {

    // SecCSFlags 在不同 SDK 里没有导出 notarization 常量，这里按 Security.framework 头文件原值定义。
    // kSecCSCheckNotarization = 0x00004000
    private static let checkNotarization = SecCSFlags(rawValue: 0x00004000)

    // kSecCodeInfoFlags 中的位定义
    private static let sigAdHoc: UInt32 = 0x00000002
    private static let sigRuntime: UInt32 = 0x00010000
    private static let sigNotarized: UInt32 = 0x02000000
    private static let sigPlatform: UInt32 = 0x04000000

    static func assess(path: String) -> SigningInfo {
        var info = SigningInfo()
        let url = URL(fileURLWithPath: path) as CFURL

        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(url, SecCSFlags(), &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            info.assessmentError = "无法创建静态代码对象: \(createStatus) \(osStatusText(createStatus))"
            return info
        }

        // 1) 基础有效性（全架构）
        let basicStatus = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), nil)
        info.valid = (basicStatus == errSecSuccess)
        if !info.valid {
            info.assessmentError = "签名校验失败(\(basicStatus)): \(osStatusText(basicStatus))"
        }

        // 2) Apple 第一方锚点: "anchor apple" 只匹配 Apple 自己签发的代码
        if let appleReq = requirement("anchor apple") {
            info.isAppleAnchored = (SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), appleReq) == errSecSuccess)
        }

        // 3) 公证检查
        var notarizedViaFlag = false
        var notarizedViaAPI = false

        // 4) 读取签名信息字典
        var cfInfo: CFDictionary?
        let copyStatus = SecCodeCopySigningInformation(code, SecCSFlags(), &cfInfo)
        if copyStatus == errSecSuccess, let dict = cfInfo as? [String: Any] {
            info.signed = true

            if let ident = dict[kSecCodeInfoIdentifier as String] as? String {
                info.identifier = ident
            }
            if let team = dict[kSecCodeInfoTeamIdentifier as String] as? String {
                info.teamID = team
            }
            if let flags = dict[kSecCodeInfoFlags as String] as? UInt32 {
                info.isAdHoc = (flags & sigAdHoc) != 0
                info.hardenedRuntime = (flags & sigRuntime) != 0
                notarizedViaFlag = (flags & sigNotarized) != 0
                info.isPlatformBinary = (flags & sigPlatform) != 0
                info.flags = describeFlags(flags)
            }
            if let certs = dict[kSecCodeInfoCertificates as String] as? [SecCertificate] {
                info.authorityChain = certs.map { certificateSummary($0) }
            }
        } else {
            // 未签名 / 无法读取签名信息
            info.signed = false
            if info.assessmentError == nil {
                info.assessmentError = "读取签名信息失败(\(copyStatus)): \(osStatusText(copyStatus))"
            }
        }

        // 注意：证书链为空不等于 ad-hoc —— 部分 Developer ID 签名经此 API 取不到证书链，
        // 但 notarization requirement 校验可通过。ad-hoc 一律以 flags 的 kSecCodeSignatureAdhoc 位为准。

        // 5) 公证：优先看 flag，再用 notarization requirement 复核
        if notarizedViaFlag { notarizedViaAPI = true }
        let notarStatus = SecStaticCodeCheckValidity(code, checkNotarization, nil)
        if notarStatus == errSecSuccess { notarizedViaAPI = true }
        info.notarized = notarizedViaAPI

        return info
    }

    // MARK: 辅助

    private static func requirement(_ text: String) -> SecRequirement? {
        var req: SecRequirement?
        return SecRequirementCreateWithString(text as CFString, SecCSFlags(), &req) == errSecSuccess ? req : nil
    }

    private static func describeFlags(_ flags: UInt32) -> [String] {
        var out: [String] = []
        if (flags & sigAdHoc) != 0 { out.append("adhoc") }
        if (flags & sigRuntime) != 0 { out.append("runtime(hardened)") }
        if (flags & sigNotarized) != 0 { out.append("notarized") }
        if (flags & sigPlatform) != 0 { out.append("platform") }
        if (flags & 0x00000100) != 0 { out.append("force-hard") }
        if (flags & 0x00000200) != 0 { out.append("force-expiration") }
        if (flags & 0x00002000) != 0 { out.append("restrict") }
        if out.isEmpty { out.append(String(format: "0x%x", flags)) }
        return out
    }

    private static func certificateSummary(_ cert: SecCertificate) -> String {
        var commonName: CFString?
        let cnStatus = SecCertificateCopyCommonName(cert, &commonName)
        let cn = (cnStatus == errSecSuccess && commonName != nil) ? (commonName! as String) : "未知证书"

        var orgUnit: String?
        if let values = SecCertificateCopyValues(cert, nil, nil) as? [String: Any] {
            if let ou = values[kSecOIDOrganizationalUnitName as String] as? [String: Any],
               let value = ou["value"] as? String {
                orgUnit = value
            }
        }
        return orgUnit != nil ? "\(cn) [\(orgUnit!)]" : cn
    }

    static func osStatusText(_ status: OSStatus) -> String {
        if let msg = SecCopyErrorMessageString(status, nil) as String? {
            return msg
        }
        switch status {
        case -67062: return "未签名 (errSecCSUnsigned)"
        case -67061: return "签名已损坏或被篡改 (errSecCSSignatureFailed)"
        case -67050: return "不满足信任要求 (errSecCSReqFailed)"
        case -67058: return "对象格式错误 (errSecCSBadObjectFormat)"
        case -67019: return "密码学参数错误 (errSecCSSignatureInvalid)"
        default: return "OSStatus \(status)"
        }
    }
}
