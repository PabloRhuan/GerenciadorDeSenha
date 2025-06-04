package service;

import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.IOException;

public class TOTPService {
    private static final long TIME_STEP_SECONDS = 30;
    private static final int CODE_DIGITS = 6;
    private static final String HMAC_ALGORITHM = "HmacSHA1";
    private static final String SECRET_FILE = "totp_secret.dat"; // Alterado para .dat

    /**
     * Gera uma nova chave secreta codificada em Base64 (uso interno).
     */
    public static String generateSecret() {
        byte[] randomBytes = new byte[20]; // 160 bits
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getEncoder().encodeToString(randomBytes);
    }

    /**
     * Converte uma chave secreta codificada em Base64 para formato Base32 (compatível com Google Authenticator).
     */
    public static String getBase32Secret(String base64secret) {
        Base32 base32 = new Base32();
        byte[] decodedBytes = Base64.getDecoder().decode(base64secret);
        return base32.encodeToString(decodedBytes).replace("=", "").replace(" ", "");
    }

    /**
     * Gera uma URL para adicionar a chave secreta no Google Authenticator via QR Code ou inserção manual.
     *
     * @param base64Secret A chave secreta codificada em Base64.
     * @param accountName  O nome da conta do usuário (ex.: usuario@exemplo.com).
     * @param issuer       O nome do aplicativo ou serviço (ex.: GerenciadorSeguro).
     * @return Uma URL completa no formato otpauth://
     */
    public static String getOtpAuthUrl(String base64Secret, String accountName, String issuer) {
        String base32Secret = getBase32Secret(base64Secret);
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s",
                issuer, accountName, base32Secret, issuer);
    }

    /**
     * Valida um código TOTP inserido pelo usuário.
     */
    public static boolean validateCode(String base64Secret, String inputCode) {
        if (inputCode == null || inputCode.length() != CODE_DIGITS) {
            System.out.println("Código TOTP inválido. Seu código deve conter " + CODE_DIGITS + " dígitos.");
            return false;
        }

        if (!inputCode.matches("\\d{" + CODE_DIGITS + "}")) {
            System.out.println("Código TOTP inválido. O código deve conter apenas números.");
            return false;
        }

        try {
            long currentWindow = Instant.now().getEpochSecond() / TIME_STEP_SECONDS;
            for (long offset = -1; offset <= 1; offset++) {
                String expectedCode = generateCodeAtTime(base64Secret, currentWindow + offset);
                if (expectedCode.equals(inputCode)) {
                    return true;
                }
            }
        } catch (Exception e) {
            System.err.println("Falha na validação do TOTP: " + e.getMessage());
            return false;
        }

        System.out.println("Tente novamente.");
        return false;
    }

    private static String generateCodeAtTime(String base64Secret, long timeWindow) throws Exception {
        byte[] key = Base64.getDecoder().decode(base64Secret);
        byte[] data = new byte[8];
        for (int i = 7; i >= 0; i--) {
            data[i] = (byte) (timeWindow & 0xFF);
            timeWindow >>= 8;
        }

        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
        byte[] hmac = mac.doFinal(data);

        int offset = hmac[hmac.length - 1] & 0xF;
        int binary = ((hmac[offset] & 0x7F) << 24)
                | ((hmac[offset + 1] & 0xFF) << 16)
                | ((hmac[offset + 2] & 0xFF) << 8)
                | (hmac[offset + 3] & 0xFF);

        int otp = binary % (int) Math.pow(10, CODE_DIGITS);
        return String.format("%0" + CODE_DIGITS + "d", otp);
    }

    /**
     * Carrega a chave secreta TOTP de um arquivo ou gera uma nova e salva.
     *
     * @return String da chave secreta codificada em Base64.
     */
    public static String loadOrCreateSecret() {
        Path path = Paths.get(SECRET_FILE);
        if (Files.exists(path)) {
            try {
                String secret = Files.readString(path).trim();
                if (!secret.isEmpty()) {
                    return secret;
                }
            } catch (IOException e) {
                System.err.println("Falha ao ler o arquivo da chave secreta: " + e.getMessage());
            }
        }
        // Gera uma nova chave secreta e salva
        String newSecret = generateSecret();
        try {
            Files.writeString(path, newSecret);
        } catch (IOException e) {
            System.err.println("Falha ao escrever o arquivo da chave secreta: " + e.getMessage());
        }
        return newSecret;
    }
}
