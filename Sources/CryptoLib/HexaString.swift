//
//  HexaString.swift
//  CryptoLib
//
//  Created by Javier Calatrava on 28/2/25.
//

import Foundation

public struct HexaString {
    
    private let hexaString: String
    
    public var value: String {
        return hexaString
    }
    
    public init(hexaString: String) {
//        guard //hexaString.count == 32,
//                HexaString.isHexadecimal(hexaString) else {
//            return nil
//        }
        self.hexaString = hexaString
    }
    
    public init() {
        let hexagonalString = HexaString.randomHexString(length: 32)
        self.init(hexaString: hexagonalString)
    }
    
    private static func randomHexString(length: Int) -> String {
        let hexChars = "0123456789ABCDEF"
        return String((0..<length).compactMap { _ in hexChars.randomElement() })
    }
    
    private static func isHexadecimal(_ str: String) -> Bool {
        let hexRegex = "^[0-9A-Fa-f]+$"
        return str.range(of: hexRegex, options: .regularExpression) != nil
    }
    
    func toString() -> String? {
        guard let data = self.toData() else {
            return nil
        }
        let dataStrWOPadding = data.removePKCS7Padding()
        guard let hexaStrWOPadding = dataStrWOPadding.toHexaString() else {
            return nil
        }
        
        let hexaStrWOPaddingValue = hexaStrWOPadding.value
            let numbers = stride(from: 0, to: hexaStrWOPaddingValue.count, by: 2).compactMap { index in
                let start = hexaStrWOPaddingValue.index(hexaStrWOPaddingValue.startIndex, offsetBy: index)
                let end = hexaStrWOPaddingValue.index(start, offsetBy: 2, limitedBy: hexaStrWOPaddingValue.endIndex) ?? hexaStrWOPaddingValue.endIndex
                return UInt8(hexaStrWOPaddingValue[start..<end], radix: 16)
            }
            return String(bytes: numbers, encoding: .utf8)
        }
    
    public func toData() -> Data? {
        let hexString = hexaString.replacingOccurrences(of: " ", with: "")
        var data = Data(capacity: hexString.count / 2)
        
        for i in stride(from: 0, to: hexString.count, by: 2) {
            let startIndex = hexString.index(hexString.startIndex, offsetBy: i)
            let endIndex = hexString.index(startIndex, offsetBy: 2, limitedBy: hexString.endIndex) ?? hexString.endIndex
            let bytes = hexString[startIndex..<endIndex]
            
            if let byte = UInt8(bytes, radix: 16) {
                data.append(byte)
            } else {
                return nil
            }
        }
        
        return data
    }
}
