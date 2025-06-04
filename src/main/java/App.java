import model.Credential;
import service.AuthService;
import service.CredentialStorage;
import service.CredentialManager;
import utils.InputSanitizer;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Scanner;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class App {

    /**
     * Ponto de entrada principal do Gerenciador de Senhas Seguro.
     * Realiza autenticação e interage com o usuário via interface de linha de comando.
     *
     * @param args Argumentos de linha de comando (atualmente não utilizados).
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            new AuthService(scanner);
        } catch (Exception e) {
            System.err.println("Falha na autenticação: " + e.getMessage());
            return;
        }

        List<Credential> credentials;
        try {
            credentials = CredentialStorage.loadCredentials();
        } catch (Exception e) {
            System.err.println("Falha ao carregar as credenciais: " + e.getMessage());
            return;
        }

        CredentialManager manager = new CredentialManager(credentials);
        manager.showMenu();
    }

    /**
     * Verifica se um sufixo de hash de senha foi encontrado em vazamentos conhecidos,
     * usando a API Have I Been Pwned (HIBP).
     * A API implementa k-anonimato, enviando apenas o prefixo do hash SHA-1 para verificação.
     *
     * @param prefix Os primeiros 5 caracteres do hash SHA-1 da senha.
     * @param suffix Os caracteres restantes do hash SHA-1 da senha.
     * @return {@code true} se o sufixo foi encontrado em vazamentos; {@code false} caso contrário.
     * @throws Exception Se a validação ou a conexão falhar.
     */
    static boolean checkPwned(String prefix, String suffix) throws Exception {
        try {
            prefix = InputSanitizer.sanitize(prefix, 5, false);
            suffix = InputSanitizer.sanitize(suffix, 100, false);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Falha na validação da entrada: " + e.getMessage());
        }

        HttpURLConnection conn = getHttpURLConnection(prefix, suffix);

        try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            String line;
            while ((line = in.readLine()) != null) {
                String[] parts = line.split(":");
                if (parts.length > 0 && parts[0].equalsIgnoreCase(suffix)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Configura uma conexão HTTP para consultar a API HIBP sobre informações de vazamento de senha.
     *
     * @param prefix Os primeiros 5 caracteres do hash SHA-1 da senha.
     * @param suffix Os caracteres restantes do hash SHA-1 (usado apenas para validação).
     * @return Um objeto {@link HttpURLConnection} configurado e pronto para consultar a API.
     * @throws URISyntaxException Se o URI construído for inválido.
     * @throws IOException Se a conexão falhar.
     */
    private static HttpURLConnection getHttpURLConnection(String prefix, String suffix)
            throws URISyntaxException, IOException {

        if (!prefix.matches("[A-Fa-f0-9]{5}")) {
            throw new IllegalArgumentException("O prefixo deve conter exatamente 5 caracteres hexadecimais.");
        }
        if (!suffix.matches("[A-Fa-f0-9]+")) {
            throw new IllegalArgumentException("O sufixo deve conter apenas caracteres hexadecimais.");
        }

        URI uri = new URI("https", "api.pwnedpasswords.com", "/range/" + prefix, null);
        URL url = uri.toURL();

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        return conn;
    }
}
