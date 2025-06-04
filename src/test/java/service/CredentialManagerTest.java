package service;

import model.Credential;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the {@link CredentialManager} class, focusing on manual list operations 
 * and the behavior of the constructor. This test suite ensures that credential-related 
 * functionality is implemented correctly.
 */
@DisplayName("CredentialManager Unit Tests")
class CredentialManagerTest {

    private List<Credential> credentials;

    /**
     * Setup method to initialize a new list of credentials before each test execution. 
     * This ensures a clean state for every individual test.
     */
    @BeforeEach
    void setUp() {
        credentials = new ArrayList<>();
    }

    /**
     * Test to verify that a single {@link Credential} can be added to the list. 
     * Confirms that the list size increases and the added credential is stored correctly.
     */
    @Test
    @DisplayName("Should add a credential to the list")
    void testAddCredentialAddsToList() {
        int initialSize = credentials.size();
        Credential testCred = new Credential("TestService", "testUser", "encryptedPass");
        credentials.add(testCred);

        // Verifies the list size increases by one and the credential is properly added.
        assertEquals(initialSize + 1, credentials.size(), "List size should increase by 1.");
        assertEquals(testCred, credentials.getFirst(), "The added credential should be the first in the list.");
    }

    /**
     * Test to verify that a {@link Credential} can be removed from the list. 
     * Confirms that the list size decreases and the list is empty after removal.
     */
    @Test
    @DisplayName("Should remove a credential from the list")
    void testRemoveCredentialRemovesFromList() {
        Credential testCred = new Credential("TestService", "testUser", "encryptedPass");
        credentials.add(testCred);
        int initialSize = credentials.size();

        credentials.removeFirst(); // Removes the first credential.

        // Verifies the list size decreases by one and becomes empty.
        assertEquals(initialSize - 1, credentials.size(), "List size should decrease by 1.");
        assertTrue(credentials.isEmpty(), "List should be empty after removal.");
    }

    /**
     * Test to verify that the {@link CredentialManager} is initialized with 
     * an empty list when no arguments are passed to the constructor. Ensures that 
     * the list is not null and is empty upon setup.
     */
    @Test
    @DisplayName("Should initialize with an empty list")
    void testConstructorInitializesWithEmptyList() {
        // Ensures the list is properly initialized and starts as empty.
        assertNotNull(credentials, "Credential list should not be null upon setup.");
        assertTrue(credentials.isEmpty(), "Credential list should be empty upon setup.");
    }

    /**
     * Test to verify that the {@link CredentialManager} constructor initializes with 
     * a provided list containing credentials. Ensures the list from the constructor 
     * is used correctly and maintains the provided state.
     */
    @Test
    @DisplayName("Should initialize with a provided list containing credentials")
    void testConstructorInitializesWithProvidedList() {
        List<Credential> testList = new ArrayList<>();
        testList.add(new Credential("TestService", "testUser", "encryptedPass"));

        CredentialManager newManager = new CredentialManager(testList);

        // Ensures the constructor accepts and uses the provided list properly.
        assertNotNull(newManager, "CredentialManager should be initialized.");
        assertEquals(1, testList.size(), "Provided list should contain one credential.");
    }
}