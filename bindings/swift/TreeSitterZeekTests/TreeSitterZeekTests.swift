import XCTest
import SwiftTreeSitter
import TreeSitterZeek

final class TreeSitterZeekTests: XCTestCase {
    func testCanLoadGrammar() throws {
        let parser = Parser()
        let language = Language(language: tree_sitter_zeek())
        XCTAssertNoThrow(try parser.setLanguage(language),
                         "Error loading Zeek grammar")
    }
}
