package model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the {@link Credential} record.
 * <p>
 * These tests validate the proper creation and usage of {@link Credential},
 * including its {@code toString()}, equality logic, and {@code hashCode} behavior.
 */
@DisplayName("CredentialTest Suite") // Display the name for the test class
class CredentialTest {

    /**
     * Tests the correct creation of a {@link Credential} object with valid field values.
     */
    @Test
    @DisplayName("Should create Credential with correct field values")
    void testCredentialCreation() {
        Credential credential = new Credential("Gmail", "user@example.com", "encryptedPass123");

        assertNotNull(credential);
        assertEquals("Gmail", credential.serviceName());
        assertEquals("user@example.com", credential.username());
        assertEquals("encryptedPass123", credential.encryptedPassword());
    }

    /**
     * Verifies the {@code toString()} method returns a correctly formatted string representation.
     */
    @Test
    @DisplayName("Should return expected string from toString()")
    void testToString() {
        Credential credential = new Credential("Gmail", "user@example.com", "encryptedPass123");
        String expected = "Service: Gmail, Username: user@example.com";

        assertEquals(expected, credential.toString());
    }

    /**
     * Validates equality between two {@link Credential} objects with the same fields
     * and ensures objects with differing fields are not considered equal.
     */
    @Test
    @DisplayName("Should consider credentials equal when fields match")
    void testEquality() {
        Credential credential1 = new Credential("Gmail", "user@example.com", "encryptedPass123");
        Credential credential2 = new Credential("Gmail", "user@example.com", "encryptedPass123");
        Credential differentCredential = new Credential("Outlook", "user@example.com", "encryptedPass123");

        assertEquals(credential1, credential2);
        assertNotEquals(credential1, differentCredential);
    }

    /**
     * Confirms that the {@code hashCode()} method produces consistent results for {@link Credential}
     * objects with the same field values.
     */
    @Test
    @DisplayName("Should return same hashCode for equal credentials")
    void testHashCode() {
        Credential credential1 = new Credential("Gmail", "user@example.com", "encryptedPass123");
        Credential credential2 = new Credential("Gmail", "user@example.com", "encryptedPass123");

        assertEquals(credential1.hashCode(), credential2.hashCode());
    }
}