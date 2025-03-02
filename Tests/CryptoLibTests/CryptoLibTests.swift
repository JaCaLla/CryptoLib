import Testing
import Crypto
import CryptoKit
@testable import CryptoLib

@Test func testEncryptionDecryption() async throws {
    let originalText = "Hola, mundo!"
    let originalData = originalText.data(using: .utf8)!

    if let encryptedData = try await AESCipher.encryptAES(data: originalData) {
        let decryptedData = try await AESCipher.decryptAES(encryptedData: encryptedData)
        #expect(originalData == decryptedData)
    } else {
        #expect(Bool(false))
    }
}


@Test func testAsymetricEncryptWitPrivateKeyDecryptWithSerialized() throws {
    if let (privateKey, publicKey) = AESCipher.generateRSAKeyPair(),
       let publicKeyData = AESCipher.convertSecKeyToData(secKey: publicKey) {
        
        let publicKeyDataHexaStr = publicKeyData.toHexaString()
        
        guard let rawRepresentation =  publicKeyDataHexaStr?.toData(),
              let pubKeyDataFromHexaStr = AESCipher.convertPublicKeyDataToSecKey(data: rawRepresentation) else {
            Issue.record("Error al convertir hexa string a data")
            return
        }
        
        let message = "Hello, World!"
        
        if let encryptedData = AESCipher.encryptWithPrivateKey(message: message, privateKey: privateKey) {
            print("Encrypted (with private key):", encryptedData.base64EncodedString())
            
            if let decryptedMessage = AESCipher.decryptWithPublicKey(encryptedData: encryptedData, publicKey: pubKeyDataFromHexaStr) {
                print("Decrypted (with public key):", decryptedMessage)
            } else {
                print("Failed to decrypt")
            }
        } else {
            print("Encryption failed")
        }
    }
}

@Test func testAsymetricEncryptWitPrivateKey() async throws {
    if let (privateKey, publicKey) = AESCipher.generateRSAKeyPair() {
        let message = "Hello, World!"
        
        if let encryptedData = AESCipher.encryptWithPrivateKey(message: message, privateKey: privateKey) {
            print("Encrypted (with private key):", encryptedData.base64EncodedString())
            
            if let decryptedMessage = AESCipher.decryptWithPublicKey(encryptedData: encryptedData, publicKey: publicKey) {
                print("Decrypted (with public key):", decryptedMessage)
            } else {
                print("Failed to decrypt")
            }
        } else {
            print("Encryption failed")
        }
    }
}

@Test func testAsymetricEncryptionDecryption() async throws {
    let (privateKey, publicKey) = AESCipher.generateKeyPair()
    let message = "Hola, mundo!"

    if let cipherText = AESCipher.encryptMessage(message: message, with: publicKey) {
        print("Mensaje cifrado:", cipherText.base64EncodedString())

        if let decryptedMessage = AESCipher.decryptMessage(cipherText: cipherText, with: privateKey, senderPublicKey: publicKey) {
            print("Mensaje descifrado:", decryptedMessage)
        } else {
            print("Fallo en el descifrado")
        }
    }
}

//https://testprotect.com/appendix/AEScalc
@Test func testConversionHexa() async throws {
    let value = HexaString(hexaString: "000102030405060708090A0B0C0D0E0F")
    guard let data = value.toData() else {
        #expect(Bool(false))
        return
    }
    #expect(data.toHexaString()?.value == value.value)
}

@Test func testString2HexaString() async throws {
    let hexaString = HexaString(hexaString: "486F6C612C206D756E646F2104040404")
    guard let convertedString = hexaString.toString() else {
        #expect(Bool(false))
        return
    }
    #expect(convertedString == "Hola, mundo!")
}

@Test func tesToHexaString() async throws {
    let value = "Hola, mundo!"
    guard let hexaString = value.toHexaString() else {
        #expect(Bool(false))
        return
    }
    #expect(hexaString.value == "486F6C612C206D756E646F2104040404")
}

