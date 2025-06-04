package utils;

public class InputSanitizer {
    /**
     * Construtor privado para evitar que a classe seja instanciada.
     */
    private InputSanitizer() {
        // Classe utilitária, não deve ser criada como objeto
    }

    /**
     * Limpa a entrada do usuário para evitar possíveis ataques, como injeção de código.
     *
     * @param input           Texto digitado pelo usuário.
     * @param maxLength       Tamanho máximo permitido para o texto.
     * @param numericOnly     Define se a entrada deve conter apenas números.
     * @return Texto limpo e seguro.
     * @throws IllegalArgumentException Se a entrada for nula, inválida ou perigosa.
     */
    public static String sanitize(String input, int maxLength, boolean numericOnly) throws IllegalArgumentException {
        if (input == null) {
            throw new IllegalArgumentException("O texto não pode ser nulo.");
        }
        input = input.trim(); // remove espaços extras no início e fim
        if (input.isEmpty() || input.length() > maxLength) {
            throw new IllegalArgumentException("O texto está vazio ou ultrapassa o limite permitido.");
        }
        if (numericOnly && !input.matches("\\d+")) {
            throw new IllegalArgumentException("O texto deve conter apenas números.");
        }
        if (!numericOnly && input.indexOf(';') >= 0 || 
                    input.indexOf('\'') >= 0 ||
                    input.indexOf('"') >= 0 ||
                    input.indexOf('<') >= 0 ||
                    input.indexOf('>') >= 0 ||
                    input.indexOf(',') >= 0) {
            throw new IllegalArgumentException("O texto contém caracteres perigosos.");
        }
        return input;
    }

    /**
     * Converte caracteres especiais para que o texto possa ser registrado em logs com segurança.
     *
     * @param input Texto fornecido pelo usuário.
     * @return Texto com os caracteres perigosos convertidos.
     */
    public static String escapeForLog(String input) {
        if (input == null) {
            return null;
        }
        return input.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }
}
