// The Swift Programming Language
// https://docs.swift.org/swift-book

import Crypto
import Foundation

public struct AESCipher {
    public static func encryptAES(/*key: SymmetricKey,*/ data: Data) async throws -> Data? {
        guard let key = await fetchMasterKey() else { return nil }
        
        let sealedBox = try AES.GCM.seal(data, using: key)
        return sealedBox.combined!
    }

    public static func decryptAES(/*key: SymmetricKey,*/ encryptedData: Data) async throws -> Data? {
        guard let key = await fetchMasterKey() else { return nil }
        let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
        return try AES.GCM.open(sealedBox, using: key)
    }
    
    private static func fetchMasterKey() async -> SymmetricKey? {
        guard let masterKey = await Environment.fetch(key: "MASTER_KEY"),
              let masterKeyData = HexaString(hexaString: masterKey).toData() else {
            return nil
        }
        return SymmetricKey(data: masterKeyData)
    }
    
    public static func generateKeyPair() -> (privateKey: P256.KeyAgreement.PrivateKey, publicKey: P256.KeyAgreement.PublicKey) {
        let privateKey = P256.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        return (privateKey, publicKey)
    }

    public static func encryptMessage(message: String, with publicKey: P256.KeyAgreement.PublicKey) -> Data? {
        guard let messageData = message.data(using: .utf8) else { return nil }

        // Generamos una clave efímera para realizar el acuerdo de clave
        let ephemeralPrivateKey = P256.KeyAgreement.PrivateKey()
        
        // Se realiza un acuerdo de clave entre la clave efímera y la clave pública del receptor
        let sharedSecret = try? ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: publicKey)
        
        // Derivar una clave simétrica a partir del secreto compartido
        let symmetricKey = sharedSecret?.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: "someSalt".data(using: .utf8)!,
            sharedInfo: Data(),
            outputByteCount: 32
        )
        
        // Cifrar con AES-GCM usando la clave derivada
        if let key = symmetricKey {
            let sealedBox = try? AES.GCM.seal(messageData, using: SymmetricKey(data: key))
            return sealedBox?.combined
        }
        
        return nil
    }

    public static func decryptMessage(cipherText: Data, with privateKey: P256.KeyAgreement.PrivateKey, senderPublicKey: P256.KeyAgreement.PublicKey) -> String? {
        // Se realiza el acuerdo de clave con la clave privada receptora y la clave pública del emisor
        let sharedSecret = try? privateKey.sharedSecretFromKeyAgreement(with: senderPublicKey)
        
        // Derivar una clave simétrica a partir del secreto compartido
        let symmetricKey = sharedSecret?.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: "someSalt".data(using: .utf8)!,
            sharedInfo: Data(),
            outputByteCount: 32
        )
        
        if let key = symmetricKey {
            if let sealedBox = try? AES.GCM.SealedBox(combined: cipherText),
               let decryptedData = try? AES.GCM.open(sealedBox, using: SymmetricKey(data: key)) {
                return String(data: decryptedData, encoding: .utf8)
            }
        }
        
        return nil
    }
    
    // MARK: - Generate RSA Key Pair
    public static func generateRSAKeyPair() -> (SecKey, SecKey)? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048
        ]
        
        var privateKey: SecKey?
        var publicKey: SecKey?
        
        let status = SecKeyGeneratePair(attributes as CFDictionary, &publicKey, &privateKey)
        guard status == errSecSuccess else { return nil }
        return (privateKey!, publicKey!)
    }
    
    public static func convertSecKeyToData(secKey: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        if let cfData = SecKeyCopyExternalRepresentation(secKey, &error) {
            return cfData as Data
        } else {
            if let error = error?.takeRetainedValue() {
                print("Error converting SecKey to Data: \(error)")
            }
            return nil
        }
    }
    
    public static func convertPublicKeyDataToSecKey(data: Data) -> SecKey? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 2048,
        ]
        
        return SecKeyCreateWithData(data as CFData, attributes as CFDictionary, nil)
    }

    // MARK: - Encrypt with Private Key
    public static func encryptWithPrivateKey(message: String, privateKey: SecKey) -> Data? {
        guard let messageData = message.data(using: .utf8) else { return nil }
        
        var error: Unmanaged<CFError>?
        let encryptedData = SecKeyCreateSignature(
            privateKey,
            .rsaEncryptionPKCS1,
            messageData as CFData,
            &error
        )
        
        return encryptedData as Data?
    }

    // MARK: - Decrypt with Public Key
    public static func decryptWithPublicKey(encryptedData: Data, publicKey: SecKey) -> String? {
        var error: Unmanaged<CFError>?
        let decryptedData = SecKeyCreateDecryptedData(
            publicKey,
            .rsaEncryptionPKCS1,
            encryptedData as CFData,
            &error
        )
        
        guard let data = decryptedData as Data? else { return nil }
        return String(data: data, encoding: .utf8)
    }
    
    // Convert Data to Hex String
    func dataToHexString(_ data: Data) -> String {
        return data.map { String(format: "%02x", $0) }.joined()
    }

    // Extract Public Key and Convert to Hex
    func publicKeyToHexString(publicKey: SecKey) -> String? {
        guard let keyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else { return nil }
        return dataToHexString(keyData)
    }
    
    // Convert Hex String to Data
    func hexStringToData(_ hex: String) -> Data? {
        var data = Data()
        var hexStr = hex
        while hexStr.count > 0 {
            let subIndex = hexStr.index(hexStr.startIndex, offsetBy: 2)
            let byteStr = String(hexStr[..<subIndex])
            hexStr = String(hexStr[subIndex...])
            if let num = UInt8(byteStr, radix: 16) {
                data.append(num)
            } else {
                return nil
            }
        }
        return data
    }

    // Convert Hex String to Public Key
    func hexStringToPublicKey(_ hexString: String) -> SecKey? {
        guard let keyData = hexStringToData(hexString) else { return nil }
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 2048
        ]
        
        return SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, nil)
    }

}

extension String {
    public func toHexaString() -> HexaString? {
        guard let data = self.data(using: .utf8) else { return nil }
        let dataWithPadding = data.addPKCS7Padding()
        return dataWithPadding.toHexaString()
    }
}

extension Data {
    public func toHexaString() -> HexaString? {
        let hexaString = map { String(format: "%02 X", $0) }.joined().uppercased()
        return HexaString(hexaString: hexaString)
    }
    
    public func addPKCS7Padding(blockSize: Int = 16) -> Data {
        let paddingLength = blockSize - (self.count % blockSize)
        let paddingBytes = [UInt8](repeating: UInt8(paddingLength), count: paddingLength)
        return self + Data(paddingBytes)
    }
    
    public func removePKCS7Padding() -> Data {
        guard let lastByte = self.last else { return self }
        let paddingLength = Int(lastByte)
        guard paddingLength <= self.count else { return self }
        return self.dropLast(paddingLength)
    }
}
