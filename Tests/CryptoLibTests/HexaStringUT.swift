//
//  Test.swift
//  CryptoLib
//
//  Created by Javier Calatrava on 28/2/25.
//
@testable import CryptoLib
import Testing

@Suite("Hexa String treatement unit test") struct HexaStringUT {
    
    @Test func initRandom() async throws {
        let hexaString = HexaString()
        #expect(hexaString.value.count == 32)
        #expect(hexaString.value.range(of: "^[0-9A-Fa-f]+$", options: .regularExpression) != nil)
    }

    @Test func testToString() async throws {
        let hexaString = HexaString(hexaString: "486F6C612C206D756E646F2104040404")
        let string = hexaString.toString()
        #expect( string == "Hola, mundo!")
    }
    
    @Test func testToData() async throws {
        let hexaString = HexaString(hexaString: "486F6C612C206D756E646F2104040404")
        #expect(hexaString.toData()?.toHexaString()?.toString() == "Hola, mundo!")
    }

}

