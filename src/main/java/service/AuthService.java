package service;

import utils.InputSanitizer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;
import java.util.regex.Pattern;
import org.mindrot.jbcrypt.BCrypt;

/**
 * Gerencia a autenticação do usuário com senha mestre e verificação TOTP.
 * Garante acesso seguro usando credenciais criptografadas e códigos baseados em tempo.
 */
public class AuthService {

    private static final String PASSWORD_FILE = "master_password.dat";
    private static final int MAX_ATTEMPTS = 3;
    private static final int MAX_PASSWORD_LENGTH = 64;
    private static final int MAX_TOTP_LENGTH = 6;
    private static final Pattern NUMBER_PATTERN = Pattern.compile("\\d+");

    private final Scanner scanner;

    /**
     * Construtor do AuthService, inicializando a autenticação com
     * validação de senha e TOTP.
     * Gera ou carrega um segredo seguro.
     *
     * @param scanner Scanner usado para ler entradas do usuário.
     * @throws Exception se a autenticação falhar após o número máximo de tentativas.
     */
    public AuthService(Scanner scanner) throws Exception {
        this.scanner = scanner;
        String masterPasswordHash = loadOrCreatePassword();
        String totpSecret = TOTPService.loadOrCreateSecret();

        System.out.println("\nAutenticação em dois fatores (TOTP) está habilitada.");
        System.out.println("Use este segredo no seu aplicativo autenticador se ainda não estiver cadastrado:");
        System.out.println(TOTPService.getBase32Secret(totpSecret));
        System.out.println("Ou escaneie um QR Code usando esta URL:");
        System.out.println(TOTPService.getOtpAuthUrl(totpSecret, "user@example.com", "SecurePasswordManager"));

        String sessionPassword = null;

        for (int attempts = 1; attempts <= MAX_ATTEMPTS; attempts++) {
            try {
                System.out.print("\nDigite a senha mestre: ");
                String inputPassword = InputSanitizer.sanitize(scanner.nextLine(), MAX_PASSWORD_LENGTH, false);

                if (!BCrypt.checkpw(inputPassword, masterPasswordHash)) {
                    System.out.println("Senha incorreta.");
                    continue;
                }

                System.out.print("Digite o código TOTP atual: ");
                String inputCode = InputSanitizer.sanitize(scanner.nextLine(), MAX_TOTP_LENGTH, true);

                if (!NUMBER_PATTERN.matcher(inputCode).matches()) {
                    throw new IllegalArgumentException("Apenas números são permitidos neste campo.");
                }

                if (TOTPService.validateCode(totpSecret, inputCode)) {
                    System.out.println("Autenticação bem-sucedida.");
                    sessionPassword = inputPassword;
                    break;
                }
            } catch (IllegalArgumentException ex) {
                System.out.println("Entrada inválida. " + InputSanitizer.escapeForLog(ex.getMessage()));
            }
        }

        if (sessionPassword == null) {
            throw new Exception("Falha na autenticação após o número máximo de tentativas.");
        }

        String salt = EncryptionService.getOrCreatePersistentSalt();
        EncryptionService.setSessionKeyAndSalt(sessionPassword, salt);
    }

    /**
     * Carrega o hash da senha mestre existente ou solicita ao usuário que crie uma nova.
     * Verifica a senha contra vazamentos conhecidos e aplica um comprimento mínimo.
     *
     * @return O hash da senha mestre.
     * @throws Exception se houver falha ao ler ou gravar o arquivo da senha.
     */
    String loadOrCreatePassword() throws Exception {
        Path path = Paths.get(PASSWORD_FILE);

        if (Files.exists(path)) {
            return Files.readString(path).trim();
        }

        System.out.println("Nenhuma senha mestre encontrada. Por favor, crie uma agora.");

        String newPassword;

        while (true) {
            try {
                System.out.print("Nova senha: ");
                newPassword = InputSanitizer.sanitize(scanner.nextLine(), MAX_PASSWORD_LENGTH, false);

                int breachCount = PasswordBreachChecker.checkPassword(newPassword);
                if (breachCount < 0) {
                    System.out.println("Erro ao verificar a senha em vazamentos conhecidos. Por favor, tente novamente.");
                    continue;
                } else if (breachCount > 0) {
                    System.out.printf(
                            "Esta senha apareceu em %d vazamento(s). Escolha uma senha mais forte.%n",
                            breachCount
                    );
                    continue;
                }

                if (newPassword.length() < 8) {
                    System.out.println("A senha deve ter no mínimo 8 caracteres. Por favor, tente novamente.");
                    continue;
                }

                System.out.print("Digite novamente a senha mestre para confirmar: ");
                String inputPassword = InputSanitizer.sanitize(scanner.nextLine(), MAX_PASSWORD_LENGTH, false);

                if (!newPassword.equals(inputPassword)) {
                    System.out.println("As senhas não coincidem. Por favor, tente novamente.");
                    continue;
                }

                break;
            } catch (IllegalArgumentException ex) {
                System.out.println("Entrada inválida. " + InputSanitizer.escapeForLog(ex.getMessage()));
            }
        }

        String hash = BCrypt.hashpw(newPassword, BCrypt.gensalt());
        Files.writeString(path, hash);
        System.out.println("Senha mestre salva.");
        return hash;
    }
}
