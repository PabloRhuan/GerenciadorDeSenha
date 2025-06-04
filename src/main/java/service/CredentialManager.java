package service;

import model.Credential;
import utils.InputSanitizer;
import utils.PasswordGenerator;
import org.mindrot.jbcrypt.BCrypt;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.Toolkit;
import java.io.IOException;
import java.util.List;
import java.util.Scanner;

/**
 * Gerencia a interação do usuário para administrar credenciais, incluindo
 * listar, adicionar, remover, buscar, descriptografar e copiar senhas.
 */
public class CredentialManager {
	private final List<Credential> credentials;
	private final Scanner scanner = new Scanner(System.in);

	/**
	 * Inicializa o gerenciador de credenciais com uma lista de credenciais.
	 *
	 * @param credentials As credenciais para gerenciar.
	 */
	public CredentialManager(List<Credential> credentials) {
		this.credentials = credentials;
	}

	/**
	 * Exibe o menu interativo para gerenciar credenciais.
	 */
	public void showMenu() {
		while (true) {
			System.out.println("\n=== Gerenciador de Credenciais ===");
			System.out.println("1. Listar todas as credenciais");
			System.out.println("2. Adicionar nova credencial");
			System.out.println("3. Remover uma credencial");
			System.out.println("4. Copiar senha para a área de transferência");
			System.out.println("5. Verificar se alguma senha foi comprometida");
			System.out.println("6. Sair");
			System.out.print("Escolha uma opção: ");
			String option = scanner.nextLine();

			switch (option) {
				case "1" -> listCredentials();
				case "2" -> addCredential();
				case "3" -> removeCredential();
				case "4" -> copyPasswordToClipboard();
				case "5" -> checkCompromisedPasswords();
				case "6" -> {
					saveAndExit();
					return;
				}
				default -> System.out.println("Opção inválida. Tente novamente.");
			}
		}
	}

	/**
	 * Lista todas as credenciais armazenadas com índice, nome do serviço e nome de usuário.
	 */
	private void listCredentials() {
		if (credentials.isEmpty()) {
			System.out.println("Nenhuma credencial armazenada.");
			return;
		}
		System.out.println("Credenciais armazenadas:");
		for (int i = 0; i < credentials.size(); i++) {
			Credential c = credentials.get(i);
			System.out.printf("%d. Serviço: %s | Usuário: %s%n", i + 1, c.serviceName(), c.username());
		}
	}

	/**
	 * Adiciona uma nova credencial, com opção de gerar uma senha segura.
	 */
	void addCredential() {
		String service;
		String username;
		String choice;

		try {
			System.out.print("Digite o nome do serviço: ");
			service = InputSanitizer.sanitize(scanner.nextLine(), 50, false);

			System.out.print("Digite o nome de usuário: ");
			username = InputSanitizer.sanitize(scanner.nextLine(), 50, false);

			System.out.print("Gerar senha forte? (s/n): ");
			choice = InputSanitizer.sanitize(scanner.nextLine().toLowerCase(), 1, false);

			// Validação da escolha do usuário
			while (!choice.equals("s") && !choice.equals("n")) {
				System.out.print("Entrada inválida. Digite 's' para sim ou 'n' para não: ");
				choice = InputSanitizer.sanitize(scanner.nextLine().toLowerCase(), 1, false);
			}
		} catch (IllegalArgumentException ex) {
			System.out.println("Entrada inválida. " + ex.getMessage());
			return;
		}

		// Define a senha com base na escolha do usuário
		String password;
		if (choice.equals("s")) {
			int passwordLength = askPasswordLength();
			boolean includeUppercase = askIncludeOption("Incluir letras maiúsculas?");
			boolean includeLowercase = askIncludeOption("Incluir letras minúsculas?");
			boolean includeNumbers = askIncludeOption("Incluir números?");
			boolean includeSymbols = askIncludeOption("Incluir símbolos?");

			if (!includeUppercase && !includeLowercase && !includeNumbers && !includeSymbols) {
				System.out.println("Erro: Pelo menos um tipo de caractere deve ser selecionado.");
				return;
			}

			password = PasswordGenerator.generate(passwordLength, includeUppercase, includeLowercase, includeNumbers, includeSymbols);

		} else {
			System.out.print("Digite a senha: ");
			try {
				password = InputSanitizer.sanitize(scanner.nextLine(), 64, false);
			} catch (IllegalArgumentException ex) {
				System.out.println("Senha inválida. " + ex.getMessage());
				return;
			}
		}

		// Criptografa e armazena a nova credencial
		try {
			String encryptedPassword = EncryptionService.encrypt(password);
			credentials.add(new Credential(service, username, encryptedPassword));
			System.out.println("Credencial adicionada com sucesso.");
		} catch (Exception e) {
			System.err.println("Erro ao criptografar a senha: " + e.getMessage());
		}
	}

	/**
	 * Pergunta ao usuário o tamanho da senha e valida a entrada.
	 *
	 * @return O tamanho da senha.
	 */
	private int askPasswordLength() {
		int length = 0;
		while (length <= 0) {
			try {
				System.out.print("Digite o tamanho da senha (mínimo 8): ");
				length = Integer.parseInt(scanner.nextLine());
				if (length < 8) {
					System.out.println("A senha deve ter no mínimo 8 caracteres.");
					length = 0;
				}
			} catch (NumberFormatException e) {
				System.out.println("Entrada inválida. Digite um número válido.");
			}
		}
		return length;
	}

	/**
	 * Pergunta se o usuário deseja incluir um conjunto específico de caracteres na senha.
	 *
	 * @param message A mensagem para exibir ao usuário.
	 * @return True se o usuário deseja incluir, false caso contrário.
	 */
	private boolean askIncludeOption(String message) {
		while (true) {
			System.out.print(message + " (s/n): ");
			String input = scanner.nextLine().toLowerCase();
			if (input.equals("s")) {
				return true;
			} else if (input.equals("n")) {
				return false;
			} else {
				System.out.println("Entrada inválida. Digite 's' para sim ou 'n' para não.");
			}
		}
	}

	/**
	 * Remove uma credencial da lista com base na entrada do usuário.
	 */
	void removeCredential() {
		listCredentials();
		if (credentials.isEmpty()) return;

		System.out.print("Digite o número da credencial que deseja remover: ");
		int index = getIntInput() - 1;

		if (index >= 0 && index < credentials.size()) {
			Credential removed = credentials.remove(index);
			System.out.println("Removido: " + removed.serviceName());
		} else {
			System.out.println("Índice inválido.");
		}
	}

	/**
	 * Copia uma senha descriptografada para a área de transferência após confirmar a senha mestre.
	 */
	private void copyPasswordToClipboard() {
		if (credentials.isEmpty()) {
			System.out.println("Nenhuma credencial armazenada.");
			return;
		}

		listCredentials();
		System.out.print("Digite o número da credencial para copiar a senha: ");
		int index = getIntInput() - 1;

		if (index < 0 || index >= credentials.size()) {
			System.out.println("Índice inválido.");
			return;
		}

		System.out.print("Digite novamente a senha mestre para confirmar: ");
		String inputPassword = scanner.nextLine().trim();

		try {
			java.nio.file.Path passwordPath = java.nio.file.Paths.get("master_password.dat");
			if (!java.nio.file.Files.exists(passwordPath)) {
				System.out.println("Arquivo master_password.dat não encontrado. Configure sua senha mestre novamente.");
				return;
			}

			String storedHash = java.nio.file.Files.readAllLines(passwordPath).getFirst();
			if (!BCrypt.checkpw(inputPassword, storedHash)) {
				System.out.println("Senha mestre incorreta. Acesso negado.");
				return;
			}

			Credential selected = credentials.get(index);
			String decrypted = EncryptionService.decrypt(selected.encryptedPassword());
			copyToClipboard(decrypted);
			System.out.printf("Senha do serviço %s copiada para a área de transferência.%n", selected.serviceName());
		} catch (IOException e) {
			System.err.println("Erro ao ler master_password.dat: " + e.getMessage());
		} catch (Exception e) {
			System.err.println("Erro ao descriptografar a senha: " + e.getMessage());
		}
	}

	/**
	 * Copia uma string para a área de transferência do sistema.
	 *
	 * @param text O texto para copiar.
	 */
	private void copyToClipboard(String text) {
		try {
			StringSelection selection = new StringSelection(text);
			Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
			clipboard.setContents(selection, null);
		} catch (Exception e) {
			System.err.println("Operação da área de transferência não suportada: " + e.getMessage());
		}
	}

	/**
	 * Verifica todas as senhas armazenadas contra dados de vazamentos conhecidos.
	 */
	private void checkCompromisedPasswords() {
		if (credentials.isEmpty()) {
			System.out.println("Nenhuma credencial armazenada.");
			return;
		}
		System.out.println("Verificando se há senhas comprometidas...");
		boolean anyCompromised = false;

		for (Credential c : credentials) {
			try {
				String decrypted = EncryptionService.decrypt(c.encryptedPassword());
				int count = PasswordBreachChecker.checkPassword(decrypted);
				if (count > 0) {
					System.out.printf(
							"ATENÇÃO: A senha do serviço '%s' (usuário: %s) apareceu %d vez(es) em vazamentos!%n",
							c.serviceName(), c.username(), count
					);
					anyCompromised = true;
				}
			} catch (Exception e) {
				System.err.println("Erro ao verificar senha do serviço '" + c.serviceName() + "': " + e.getMessage());
			}
		}

		if (!anyCompromised) {
			System.out.println("Nenhuma senha comprometida foi encontrada nas suas credenciais.");
		}
	}

	/**
	 * Salva as credenciais e encerra a aplicação.
	 */
	private void saveAndExit() {
		try {
			CredentialStorage.saveCredentials(credentials);
			System.out.println("Credenciais salvas. Saindo...");
		} catch (Exception e) {
			System.err.println("Erro ao salvar credenciais: " + e.getMessage());
		}
	}

	/**
	 * Lê e valida uma entrada inteira do usuário.
	 *
	 * @return Inteiro válido ou -1 se a entrada for inválida.
	 */
	private int getIntInput() {
		try {
			return Integer.parseInt(scanner.nextLine().trim());
		} catch (NumberFormatException e) {
			System.out.println("Entrada inválida. Digite um número.");
			return -1;
		}
	}
}
