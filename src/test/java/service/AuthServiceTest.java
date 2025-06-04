package service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mindrot.jbcrypt.BCrypt;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link AuthService} class.
 * These tests validate the behavior of password loading, authentication attempts,
 * and TOTP code validation.
 */
@DisplayName("AuthService Unit Tests")
class AuthServiceTest {

    @Mock
    private Scanner mockScanner;

    /**
     * Sets up the test environment by initializing mocks before each test.
     */
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    /**
     * Tests that the hashed master password is returned when the password file exists.
     *
     * @throws Exception if reading the mock file or invoking the method fails
     */
    @Test
    @DisplayName("Should return password hash when file exists")
    void testLoadOrCreatePasswordFileExistsShouldReturnPasswordHash() throws Exception {
        Path mockPath = Path.of("master_password.dat");
        String expectedHash = BCrypt.hashpw("password123", BCrypt.gensalt());

        try (var mockedFiles = mockStatic(Files.class)) {
            mockedFiles.when(() -> Files.exists(mockPath)).thenReturn(true);
            mockedFiles.when(() -> Files.readString(mockPath)).thenReturn(expectedHash);

            AuthService authService = mock(AuthService.class);
            when(authService.loadOrCreatePassword()).thenCallRealMethod();

            String result = authService.loadOrCreatePassword();

            assertEquals(expectedHash, result);
        }
    }

    /**
     * Tests that an exception is thrown after the maximum number of incorrect master password attempts.
     */
    @Test
    @DisplayName("Should throw exception after maximum incorrect password attempts")
    void testAuthenticationMaxAttemptsShouldThrowException() {
        String fakePassword = "wrongPassword";
        when(mockScanner.nextLine()).thenReturn(fakePassword);

        assertThrows(Exception.class, () -> new AuthService(mockScanner));
    }

    /**
     * Tests that an exception is thrown when an invalid TOTP code is provided after successful password authentication.
     */
    @Test
    @DisplayName("Should throw exception for invalid TOTP code")
    void testAuthenticationInvalidTOTPShouldThrowException() {
        String correctPassword = "correctPassword";
        String incorrectTotp = "123456";
        when(mockScanner.nextLine()).thenReturn(correctPassword, incorrectTotp);

        assertThrows(Exception.class, () -> new AuthService(mockScanner));
    }
}