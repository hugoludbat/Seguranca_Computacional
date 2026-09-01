import string
import unicodedata
import os

alphabet = string.ascii_uppercase
indexDict = dict(zip(alphabet, range(len(alphabet))))
letterDict = dict(zip(range(len(alphabet)), alphabet))

ARQUIVO_TEXTO_SALVO = "ultimo_texto.txt"

FREQ_EN = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974, 'Z': 0.074
}

FREQ_PT = {
    'A': 14.63, 'B': 1.04, 'C': 3.88, 'D': 4.99, 'E': 12.57,
    'F': 1.02, 'G': 1.30, 'H': 1.28, 'I': 6.18, 'J': 0.40,
    'K': 0.02, 'L': 2.78, 'M': 4.74, 'N': 5.05, 'O': 10.73,
    'P': 2.52, 'Q': 1.20, 'R': 6.53, 'S': 7.81, 'T': 4.34,
    'U': 4.63, 'V': 1.67, 'W': 0.01, 'X': 0.21, 'Y': 0.01, 'Z': 0.47
}

# --- Normalização ------------------------------------------------------------
def normalize(text):
    # Remove acentos, caracteres especiais e converte tudo para letras maiúsculas de A a Z.
    text = unicodedata.normalize('NFKD', text)
    text = ''.join(c for c in text if not unicodedata.combining(c))
    return ''.join(c for c in text.upper() if c in alphabet)

# --- Cifra / decifra -----------------------------------------------------------
def encrypt(message, key):
    # Converte os caracteres da chave para seus índices numéricos (A=0, B=1...)
    keyindexed = [indexDict[k] for k in key]
    # Repete a chave até que ela cubra o tamanho total da mensagem original
    keyindexed = (keyindexed * (len(message)//len(keyindexed)+1))[:len(message)]
    # Aplica a fórmula matemática da Cifra de Vigenère: C_i = (P_i + K_i) mod 26
    return ''.join(letterDict[(indexDict[c] + keyindexed[i]) % 26] for i, c in enumerate(message))

def decrypt(cipher, key):
    # Converte os caracteres da chave para índices numéricos
    keyindexed = [indexDict[k] for k in key]
    keyindexed = (keyindexed * (len(cipher)//len(keyindexed)+1))[:len(cipher)]
    # Desfaz a cifra subtraindo o valor numérico da chave do valor do criptograma: P_i = (C_i - K_i) mod 26
    return ''.join(letterDict[(indexDict[c] - keyindexed[i]) % 26] for i, c in enumerate(cipher))

# --- Chi-quadrado --------------------------------------------------------------
def chi_squared_score(counts, freq_table, total):
    # Calcula a métrica Qui-quadrado comparando a contagem de letras observada no texto com a frequência natural esperada para o idioma
    chi2 = 0.0
    for letter in alphabet:
        observed = counts.get(letter, 0)
        expected = freq_table[letter] / 100.0 * total
        if expected > 0:
            chi2 += (observed - expected) ** 2 / expected
    return chi2

def best_shift_for_subset(subset, freq_table):
    # Testa todos os 26 deslocamentos possíveis (como uma cifra de César) para um subconjunto
    best_shift, best_chi2 = 0, float('inf')
    total = len(subset)
    for shift in range(26):
        decoded = [letterDict[(indexDict[c] - shift) % 26] for c in subset]
        counts = {}
        for d in decoded:
            counts[d] = counts.get(d, 0) + 1
        chi2 = chi_squared_score(counts, freq_table, total)
        # Identifica e armazena o deslocamento que gera a menor variação estatística (menor Chi2)
        if chi2 < best_chi2:
            best_chi2 = chi2
            best_shift = shift
    return best_shift, best_chi2

def most_likely_key_for_length(ciphertext, N, freq_table):
    # Divide o criptograma em N colunas e encontra o caractere mais provável da chave para cada coluna
    key_chars = []
    total_chi2 = 0.0
    for i in range(N):
        subset = ciphertext[i::N]
        if len(subset) == 0:
            continue
        shift, chi2 = best_shift_for_subset(subset, freq_table)
        key_chars.append(letterDict[shift])
        total_chi2 += chi2
    return ''.join(key_chars), total_chi2 / N

# --- Índice de Coincidência ------------------------------------------------------
def index_of_coincidence(text):
    # Calcula a probabilidade de duas letras aleatórias selecionadas serem idênticas. Ajuda a estimar o tamanho da chave
    n = len(text)
    if n <= 1:
        return 0.0
    counts = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    return sum(f * (f - 1) for f in counts.values()) / (n * (n - 1))

def avg_ic_for_length(ciphertext, N):
    # Extrai o IC médio separando o texto em subconjuntos com base no tamanho da chave N estimado
    ics = []
    for i in range(N):
        subset = ciphertext[i::N]
        if len(subset) > 1:
            ics.append(index_of_coincidence(subset))
    return sum(ics) / len(ics) if ics else 0.0

# --- Ataque completo ------------------------------------------------------------
def crack(ciphertext, max_len, freq_table):
    # Automatiza o ataque estatístico iterando sobre os possíveis tamanhos de chave de 1 a 20 (max_len)
    resultados = []
    for N in range(1, max_len + 1):
        key, chi2 = most_likely_key_for_length(ciphertext, N, freq_table)
        ic = avg_ic_for_length(ciphertext, N)
        resultados.append({'N': N, 'key': key, 'chi2': chi2, 'ic': ic})
    # Ordena os resultados para que as chaves com menor divergência do idioma nativo fiquem no topo
    resultados.sort(key=lambda r: r['chi2'])
    return resultados

# --- Persistência do texto salvo ------------------------------------------------
def salvar_texto(texto):
    with open(ARQUIVO_TEXTO_SALVO, "w", encoding="utf-8") as f:
        f.write(texto)

def carregar_texto():
    if not os.path.exists(ARQUIVO_TEXTO_SALVO):
        print("Nenhum texto salvo ainda. Digite um novo texto.")
        return None
    with open(ARQUIVO_TEXTO_SALVO, "r", encoding="utf-8") as f:
        return f.read()

def obter_texto(prompt_novo="Texto: "):
    """Pergunta se usa texto salvo ou novo, retorna o texto já normalizado."""
    escolha = input("Texto salvo (1) ou novo texto (2): ").strip()
    if escolha == "1":
        texto = carregar_texto()
        if texto is None:
            texto = input(prompt_novo)
    else:
        texto = input(prompt_novo)
    return normalize(texto)

# --- Main ------------------------------------------------------------------------
def main():
    while(True):
        print("\n--- Cifra de Vigenère ---\n")
        print("Escolha a opção:")
        print("Criptografar (1)")
        print("Descriptografar (2)")
        print("Hack (3)")
        opcao = input("> ").strip()
        if opcao == "1":
            # ------------------- CRIPTOGRAFAR -------------------
            texto = input("Texto: ")
            texto = normalize(texto)
            chave = input("Chave: ")
            chave = normalize(chave)

            if not texto:
                raise ValueError("Texto não tem caracteres A-Z válidos após normalização.")
            if not chave:
                raise ValueError("Chave não tem caracteres A-Z válidos após normalização.")

            resultado = encrypt(texto, chave)
            print("Resultado:", resultado)
            salvar_texto(resultado)
            print("(Resultado salvo como texto salvo para uso futuro)")

        elif opcao == "2":
            # ------------------- DESCRIPTOGRAFAR -------------------
            texto = obter_texto("Texto: ")
            chave = input("Chave: ")
            chave = normalize(chave)

            if not texto:
                raise ValueError("Texto não tem caracteres A-Z válidos após normalização.")
            if not chave:
                raise ValueError("Chave não tem caracteres A-Z válidos após normalização.")

            resultado = decrypt(texto, chave)
            print("Resultado:", resultado)
            salvar_texto(resultado)
            print("(Resultado salvo como texto salvo para uso futuro)")

        elif opcao == "3":
            # ------------------- HACK -------------------
            texto = obter_texto("Texto (criptografado): ")
            idioma = input("Texto português (1) ou inglês (2): ").strip()
            freq_table = FREQ_PT if idioma == "1" else FREQ_EN

            resultados = crack(texto, max_len=20, freq_table=freq_table)

            melhor = resultados[0]
            print("\nResultado:", decrypt(texto, melhor['key']))
            print("\nChaves prováveis (top 5, ordenadas por chi²):")
            print(f"{'N':>3} | {'chave candidata':<20} | {'chi2':>10} | {'IC':>7}")
            for r in resultados[:5]:
                print(f"{r['N']:>3} | {r['key']:<20} | {r['chi2']:>10.2f} | {r['ic']:>7.4f}")

        else:
            print("Opção inválida.")

if __name__ == "__main__":
    main()
