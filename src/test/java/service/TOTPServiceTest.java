package service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Base64;

/**
 * Unit tests for the {@link TOTPService} class.
 * These tests cover secret generation, encoding, URL creation, and TOTP code validation.
 */
@DisplayName("Tests for TOTPService")
public class TOTPServiceTest {

    private static final String TEST_ACCOUNT = "test@example.com";
    private static final String TEST_ISSUER = "TestApp";

    /**
     * Tests if the generated secret is a valid Base64-encoded string
     * and has the expected decoded length of 20 bytes (160 bits).
     */
    @Test
    @DisplayName("Should generate valid Base64 secret")
    void testGenerateSecret() {
        String secret = TOTPService.generateSecret();
        assertNotNull(secret);
        assertDoesNotThrow(() -> Base64.getDecoder().decode(secret));
        assertEquals(20, Base64.getDecoder().decode(secret).length);
    }

    /**
     * Tests conversion of a Base64-encoded secret to a Base32 string.
     * Ensures the result contains only valid Base32 characters and no padding.
     */
    @Test
    @DisplayName("Should convert Base64 secret to Base32 format")
    void testGetBase32Secret() {
        String base64Secret = TOTPService.generateSecret();
        String base32Secret = TOTPService.getBase32Secret(base64Secret);

        assertNotNull(base32Secret);
        assertTrue(base32Secret.matches("^[A-Z2-7]+$"));
        assertFalse(base32Secret.contains("="));
        assertFalse(base32Secret.contains(" "));
    }

    /**
     * Tests the construction of the OTP Auth URL using the Base64 secret,
     * user account name, and issuer.
     */
    @Test
    @DisplayName("Should generate valid OTP Auth URL")
    void testGetOtpAuthUrl() {
        String base64Secret = TOTPService.generateSecret();
        String url = TOTPService.getOtpAuthUrl(base64Secret, TEST_ACCOUNT, TEST_ISSUER);

        assertNotNull(url);
	    //noinspection SpellCheckingInspection
	    assertTrue(url.startsWith("otpauth://totp/"));
        assertTrue(url.contains(TEST_ACCOUNT));
        assertTrue(url.contains(TEST_ISSUER));
        assertTrue(url.contains("secret="));
    }

    /**
     * Nested test class for validating different TOTP code scenarios.
     */
    @Nested
    @DisplayName("TOTP Code Validation Tests")
    class ValidationTests {

        private String base64Secret;

        /**
         * Generates a new Base64 secret before each validation test.
         */
        @BeforeEach
        void setUp() {
            base64Secret = TOTPService.generateSecret();
        }

        /**
         * Tests that a null TOTP code is rejected during validation.
         */
        @Test
        @DisplayName("Should reject null code")
        void testValidateNullCode() {
            assertFalse(TOTPService.validateCode(base64Secret, null));
        }

        /**
         * Tests that TOTP codes with invalid length (not 6 digits) are rejected.
         */
        @Test
        @DisplayName("Should reject invalid code length")
        void testValidateInvalidLength() {
            assertFalse(TOTPService.validateCode(base64Secret, "12345"));
            assertFalse(TOTPService.validateCode(base64Secret, "1234567"));
        }

        /**
         * Tests that non-numeric TOTP codes are rejected.
         */
        @Test
        @DisplayName("Should reject non-numeric code")
        void testValidateNonNumeric() {
	        //noinspection SpellCheckingInspection
	        assertFalse(TOTPService.validateCode(base64Secret, "abcdef"));
        }
    }

    /**
     * Tests the fallback method that either loads an existing secret or generates a new one.
     */
    @Test
    @DisplayName("Should load or create secret successfully")
    void testLoadOrCreateSecret() {
        String secret = TOTPService.loadOrCreateSecret();
        assertNotNull(secret);
        assertDoesNotThrow(() -> Base64.getDecoder().decode(secret));
    }
}
