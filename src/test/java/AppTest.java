import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Unit tests for the App class.
 * Focuses on reflection-based method detection, HTTP connectivity, and the checkPwned functionality.
 */
@DisplayName("App Class Unit Tests")
class AppTest {

    /**
     * Verifies that the App class includes a valid main method.
     */
    @Test
    @DisplayName("Should detect the existence of main(String[] args) method")
    void testMainMethodExists() {
        try {
            Method mainMethod = App.class.getDeclaredMethod("main", String[].class);
            assertNotNull(mainMethod, "The App class must include a main method.");
            assertEquals(void.class, mainMethod.getReturnType(), "The main method must return void.");
        } catch (NoSuchMethodException e) {
            fail("main(String[] args) method was not found in App class.");
        }
    }

    /**
     * Tests the checkPwned method with a syntactically invalid prefix and suffix.
     * Expects a false result without exceptions.
     */
    @Test
    @DisplayName("Should return false for invalid prefix and suffix")
    void testCheckPwnedInvalidUrl() {
        String invalidPrefix = "12345";
        String invalidSuffix = "00000";

        try {
            boolean response = App.checkPwned(invalidPrefix, invalidSuffix);
            assertFalse(response, "checkPwned should return false for invalid or unreachable URL.");
        } catch (Exception e) {
            fail("No exception should have been thrown, but was: " + e.getMessage());
        }
    }

    /**
     * Tests the checkPwned method using syntactically valid input.
     * Does not require the password to be actually pwned.
     */
    @Test
    @DisplayName("Should return false for valid prefix and suffix with no breach")
    void testCheckPwnedValidStructure() {
        String validPrefix = "00000";
        String validSuffix = "00000";

        try {
            boolean response = App.checkPwned(validPrefix, validSuffix);
            assertFalse(response, "checkPwned should return false for non-breached dummy credentials.");
        } catch (Exception e) {
            fail("No exception should be thrown for syntactically valid input.");
        }
    }

    /**
     * Tests whether a connection to the Pwned Passwords API succeeds and returns HTTP 200.
     */
    @Test
    @DisplayName("Should receive HTTP 200 OK from Pwned API for a valid request")
    void testHttpConnectionTimeout() {
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://api.pwnedpasswords.com/range/00000"))
                    .build();

            assertEquals(
                    200,
                    client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode(),
                    "HTTP connection to Pwned API should return 200 (OK)."
            );
        } catch (Exception e) {
            fail("Failed to configure HttpClient or connect to API: " + e.getMessage());
        }
    }
}
