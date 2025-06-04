package service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.net.URI;

public class PasswordBreachChecker {

    /**
     * Verifica se uma senha foi encontrada em vazamentos de dados conhecidos usando a API "Have I Been Pwned".
     * @param password A senha a ser verificada.
     * @return Número de vezes que a senha foi encontrada em vazamentos (0 = segura).
     */
    public static int checkPassword(String password) {
        try {
            // Passo 1: Gerar hash SHA-1 da senha
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] hashBytes = sha1.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02X", b));
            }
            String sha1Hash = sb.toString();
            String prefix = sha1Hash.substring(0, 5);
            String suffix = sha1Hash.substring(5);

            // Passo 2: Consultar a API com o prefixo
            URI uri = new URI("https", "api.pwnedpasswords.com", "/range/" + prefix, null);
            URL url = uri.toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith(suffix)) {
                    String[] parts = line.split(":");
                    return Integer.parseInt(parts[1].trim());
                }
            }
            reader.close();
            return 0; // Não encontrado em vazamentos

        } catch (Exception e) {
            System.err.println("Erro ao verificar vazamento de senha: " + e.getMessage());
            return -1;
        }
    }
}
