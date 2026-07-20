import Darwin
import XCTest
@testable import SupabaseOpsGuard

final class TerminalInputTests: XCTestCase {
    func testReadActionsDoNotRequireAuthentication() {
        for method in ["GET", "HEAD"] {
            let action = HTTPAction(id: "items.read", method: method, path: "/rest/v1/items")
            XCTAssertFalse(requiresAuthentication(action))
        }
    }

    func testWriteActionsRequireAuthentication() {
        for method in ["POST", "PUT", "PATCH"] {
            let action = HTTPAction(id: "items.write", method: method, path: "/rest/v1/items")
            XCTAssertTrue(requiresAuthentication(action))
        }
    }

    func testProjectURLNormalizationTrimsClipboardWhitespaceAndTrailingSlash() {
        XCTAssertEqual(
            normalizeProjectURL("  https://rubctkzqxcdgkbbcprnu.supabase.co/  \t"),
            "https://rubctkzqxcdgkbbcprnu.supabase.co"
        )
    }

    func testHiddenInputReachesReadBodyAndRestoresTerminalEcho() throws {
        var master: Int32 = -1
        var slave: Int32 = -1
        XCTAssertEqual(openpty(&master, &slave, nil, nil, nil), 0)
        defer {
            if master >= 0 { close(master) }
            if slave >= 0 { close(slave) }
        }

        var before = termios()
        XCTAssertEqual(tcgetattr(slave, &before), 0)
        XCTAssertNotEqual(before.c_lflag & tcflag_t(ECHO), 0)

        var reachedReadBody = false
        let result = try withEchoDisabled(fileDescriptor: slave) {
            reachedReadBody = true
            var during = termios()
            XCTAssertEqual(tcgetattr(slave, &during), 0)
            XCTAssertEqual(during.c_lflag & tcflag_t(ECHO), 0)
            return "entered value"
        }

        XCTAssertTrue(reachedReadBody)
        XCTAssertEqual(result, "entered value")

        var after = termios()
        XCTAssertEqual(tcgetattr(slave, &after), 0)
        XCTAssertNotEqual(after.c_lflag & tcflag_t(ECHO), 0)
    }

    func testHiddenInputRestoresTerminalEchoWhenReadBodyThrows() throws {
        var master: Int32 = -1
        var slave: Int32 = -1
        XCTAssertEqual(openpty(&master, &slave, nil, nil, nil), 0)
        defer {
            if master >= 0 { close(master) }
            if slave >= 0 { close(slave) }
        }

        XCTAssertThrowsError(
            try withEchoDisabled(fileDescriptor: slave) { () throws -> String in
                throw GuardError.message("read failed")
            }
        )

        var after = termios()
        XCTAssertEqual(tcgetattr(slave, &after), 0)
        XCTAssertNotEqual(after.c_lflag & tcflag_t(ECHO), 0)
    }
}
