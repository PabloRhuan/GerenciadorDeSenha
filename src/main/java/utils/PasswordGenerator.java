package utils;

import service.PasswordBreachChecker;
import java.security.SecureRandom;

public class PasswordGenerator {
    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String NUMBERS = "0123456789";
    private static final String SYMBOLS = "!@#$%&*()-_=+[]{}";
    private static final SecureRandom random = new SecureRandom();

    /**
     * Gera uma senha forte com base nas preferências do usuário.
     *
     * @param length           Comprimento desejado para a senha.
     * @param includeUppercase Incluir letras maiúsculas?
     * @param includeLowercase Incluir letras minúsculas?
     * @param includeNumbers   Incluir números?
     * @param includeSymbols   Incluir símbolos especiais?
     * @return Uma senha gerada aleatoriamente em formato de String.
     */
    public static String generate(int length, boolean includeUppercase, boolean includeLowercase,
                                  boolean includeNumbers, boolean includeSymbols) {
        StringBuilder characterPool = new StringBuilder();
        if (includeUppercase) characterPool.append(UPPERCASE);
        if (includeLowercase) characterPool.append(LOWERCASE);
        if (includeNumbers) characterPool.append(NUMBERS);
        if (includeSymbols) characterPool.append(SYMBOLS);

        if (characterPool.isEmpty() || length <= 0) {
            throw new IllegalArgumentException("Parâmetros inválidos para geração da senha.");
        }

        String password;
        int breachCount;
        do {
            StringBuilder passwordBuilder = new StringBuilder(length);
            for (int i = 0; i < length; i++) {
                int index = random.nextInt(characterPool.length());
                passwordBuilder.append(characterPool.charAt(index));
            }
            password = passwordBuilder.toString();
            
            // Verifica se a senha já foi exposta em vazamentos
            breachCount = PasswordBreachChecker.checkPassword(password);

            if (breachCount > 0) {
                System.out.printf("A senha gerada já apareceu em %d vazamento(s). Gerando uma senha mais segura...%n", breachCount);
            }
        } while (breachCount > 0); // Gera outra senha caso a atual já tenha sido comprometida

        return password;
    }
}
