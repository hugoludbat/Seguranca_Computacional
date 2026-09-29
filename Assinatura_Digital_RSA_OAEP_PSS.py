# Universidade de Brasilia 2026 - Seguranca Computacional
# Trabalho 2 - Sistema de Assinatura Digital e Verificação Segura de Arquivos
# Implementação unificada: RSA, OAEP e PSS

import os
import base64
from random import randrange
import json

# ==========================================================
# PARTE I - GERAÇÃO E GERENCIAMENTO DE CHAVES RSA
# ==========================================================

primos = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97]

def divisible_by_prime(number: int) -> bool:
    for p in primos:
        if number % p == 0:
            return True
    return False

def miller_rabin(number : int) -> bool:
    if number <= 1:
        return False
    if number in primos:
        return True
    if divisible_by_prime(number):
        return False

    n = int(number - 1)
    a = randrange(2, n)

    if pow(a, n, number) != 1:
        return False

    req1 = True
    while n % 2 == 0:
        n //= 2
        x = pow(a, n, number)
        if req1: 
            if x == number - 1:
                req1 = False
            elif x != 1: 
                return False
    return True

def miller_repeat(number : int, reps : int) -> bool:
    for z in range(reps):
        if not miller_rabin(number):
            return False
    return True

def get_prime(bits : int, reps : int) -> int:
    def genRandom():
        min_digit = 2**(bits - 1) # Usar base 2 em vez de 10
        max_digit = 2**bits - 1
        while True:
            num = randrange(min_digit, max_digit)
            # Para binário, garantimos que é ímpar verificando a divisão
            if num % 2 != 0: 
                return num
    i = 0
    while True:
        i += 1
        n = genRandom()
        if miller_repeat(n, reps):
            return n

def mdc(a : int, b : int) -> int:
    while b:
        a, b = b, a % b
    return a

def get_phi(p: int, q: int) -> int:
    return (p - 1) * (q - 1)

def find_e(phi : int) -> int:
    e = 65537
    if mdc(e, phi) == 1:
        return e
    e = 3
    while mdc(e, phi) != 1:
        e += 2
    return e

def mod_inverso(e : int, phi : int) -> int:
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    _, x, _ = extended_gcd(e % phi, phi)
    return (x % phi + phi) % phi

def sha3_256(message):
    # Converter string para bytes se necessário
    if isinstance(message, str):
        message = message.encode()

    # Parâmetros SHA3-256
    r = 1088  # taxa em bits (136 bytes)
    c = 512  # capacidade em bits (64 bytes)
    w = 64  # tamanho da palavra em bits
    output_length = 32  # 256 bits = 32 bytes

    # RHO - deslocamentos de rotação
    RHO = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14],
    ]

    # RC - constantes de rodada
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]

    def rot(x, n):
        # Rotação pra esquerda
        n = n % 64
        return ((x << n) | (x >> (64 - n))) & ((1 << 64) - 1)

    def keccak_f(state):
        # keccak 1600 - 24 rodadas
        for round_idx in range(24):
            state = keccak_round(state, RC[round_idx])
        return state

    def keccak_round(A, RC):
        # Rodada de keccak
        # Passo θ (theta)
        C = [0] * 5
        for x in range(5):
            C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]

        D = [0] * 5
        for x in range(5):
            D[x] = C[(x - 1) % 5] ^ rot(C[(x + 1) % 5], 1)

        for x in range(5):
            for y in range(5):
                A[x][y] = A[x][y] ^ D[x]

        # Passo ρ (rho) e π (pi)
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = rot(A[x][y], RHO[x][y])

        # Passo χ (chi)
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])
                A[x][y] &= (1 << 64) - 1  # Manter em 64 bits

        # Passo ι (iota)
        A[0][0] = A[0][0] ^ RC
        A[0][0] &= (1 << 64) - 1

        return A

    def bytes_to_state(data, r_bytes):
        # Convertendo byte pra state, ou seja blocos de 5*5*64
        state = [[0] * 5 for _ in range(5)]
        for i in range(min(len(data), r_bytes)):
            x = (i // 8) % 5
            y = (i // 8) // 5
            byte_pos = i % 8
            state[x][y] |= (data[i] << (8 * byte_pos))
        return state

    def state_to_bytes(state, length):
        # Converte blocos 5*5*64 em bytes
        output = bytearray()
        for y in range(5):
            for x in range(5):
                word = state[x][y]
                for i in range(8):
                    if len(output) < length:
                        output.append((word >> (8 * i)) & 0xFF)
        return bytes(output[:length])

    # === PADDING (Keccak padding: pad10*1) ===
    r_bytes = r // 8  # 136 bytes

    # Adicionar byte 0x06 (SHA3)
    padded = bytearray(message)
    padded.append(0x06)

    # Padding com zeros até múltiplo de r_bytes
    while len(padded) % r_bytes != 0:
        padded.append(0x00)

    # Adicionar byte 0x80 no final
    padded[-1] |= 0x80

    # === PHASE DE ABSORÇÃO ===
    state = [[0] * 5 for _ in range(5)]

    for i in range(0, len(padded), r_bytes):
        block = padded[i:i + r_bytes]
        block_state = bytes_to_state(block, r_bytes)

        # XOR com estado atual
        for x in range(5):
            for y in range(5):
                state[x][y] ^= block_state[x][y]

        # Aplicar Keccak-f
        state = keccak_f(state)

        # === PHASE DE EXTRAÇÃO ===
        output = state_to_bytes(state, output_length)

        return output

# ==========================================================
# GERENCIAMENTO DE ARQUIVOS (IMPORTAÇÃO E EXPORTAÇÃO DE CHAVES)
# ==========================================================

def exportar_chave(chave: tuple[int, int], tipo: str, nome_arquivo: str):
    """
    Exporta a chave (pública ou privada) para um arquivo no formato JSON.
    O formato escolhido pelo grupo estrutura a chave num dicionário contendo
    o tipo da chave, o módulo 'n' e o 'expoente' ('e' ou 'd').
    """
    dados_chave = {
        "tipo": tipo,
        "n": chave[0],
        "expoente": chave[1]
    }
    # Salva os dados no arquivo especificado
    with open(nome_arquivo, 'w') as arquivo:
        json.dump(dados_chave, arquivo, indent=4)

def importar_chave(nome_arquivo: str) -> tuple[int, int]:
    """
    Lê o arquivo JSON e recupera a tupla (n, expoente) para ser usada nas funções.
    """
    with open(nome_arquivo, 'r') as arquivo:
        dados = json.load(arquivo)
        
    # Retorna no formato de tupla (n, e) ou (n, d) que o resto do código já usa
    return (dados["n"], dados["expoente"])

# ==========================================================
# FUNÇÃO AUXILIAR COMPARTILHADA (MGF1)
# ==========================================================

def mgf1(seed: bytes, length: int) -> bytes:
    """Implementação do MGF1 utilizando SHA3-256."""
    counter = 0
    output = b""
    while len(output) < length:
        c = counter.to_bytes(4, byteorder='big')
        output += sha3_256(seed + c)
        counter += 1
    return output[:length]

# ==========================================================
# PARTE II - CIFRAGEM E DECIFRAGEM RSA-OAEP
# ==========================================================

def oaep_encode(mensagem_bytes: bytes, k: int, label: bytes = b"") -> bytes:
    h_len = 32 # SHA3-256 length
    if len(mensagem_bytes) > k - 2 * h_len - 2:
        raise ValueError("Mensagem muito longa para o tamanho da chave RSA.")
    
    l_hash = sha3_256(label)
    ps = b"\x00" * (k - len(mensagem_bytes) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + mensagem_bytes
    
    seed = os.urandom(h_len)
    
    db_mask = mgf1(seed, k - h_len - 1)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    
    seed_mask = mgf1(masked_db, h_len)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))
    
    return b"\x00" + masked_seed + masked_db

def oaep_decode(em: bytes, k: int, label: bytes = b"") -> bytes:
    h_len = 32
    l_hash = sha3_256(label)
    
    if em[0] != 0:
        raise ValueError("Erro de padding OAEP (Primeiro byte não é zero). Ciphertext alterado!")
        
    masked_seed = em[1:1+h_len]
    masked_db = em[1+h_len:]
    
    seed_mask = mgf1(masked_db, h_len)
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))
    
    db_mask = mgf1(seed, k - h_len - 1)
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))
    
    if l_hash != db[:h_len]:
         raise ValueError("Hash da label incorreto. Ciphertext alterado!")
         
    index = h_len
    while index < len(db) and db[index] == 0:
        index += 1
        
    if index >= len(db) or db[index] != 1:
        raise ValueError("Erro de formatação do padding. Ciphertext alterado!")
        
    return db[index+1:]

def cifrar_oaep(mensagem: str, chave: tuple[int, int]) -> int:
    n, e = chave
    k = (n.bit_length() + 7) // 8
    msg_bytes = mensagem.encode('utf-8')
    em = oaep_encode(msg_bytes, k)
    m_int = int.from_bytes(em, byteorder='big')
    return pow(m_int, e, n)

def decifrar_oaep(cifrado: int, chave_privada: tuple[int, int]) -> str:
    n, d = chave_privada
    k = (n.bit_length() + 7) // 8
    m_int = pow(cifrado, d, n)
    em = m_int.to_bytes(k, byteorder='big')
    msg_bytes = oaep_decode(em, k)
    return msg_bytes.decode('utf-8')

# ==========================================================
# PARTE III E IV - ASSINATURA DIGITAL RSA-PSS E VERIFICAÇÃO
# ==========================================================

def pss_encode(mensagem_bytes: bytes, mod_bits: int) -> bytes:
    k = (mod_bits + 7) // 8
    em_bits = mod_bits - 1 # Regra RFC 8017
    h_len = 32
    s_len = 32 
    
    m_hash = sha3_256(mensagem_bytes)
    salt = os.urandom(s_len)
    m_linha = (b'\x00' * 8) + m_hash + salt
    h = sha3_256(m_linha)
    
    ps_len = k - s_len - h_len - 2
    if ps_len < 0:
        raise ValueError("Chave muito pequena para PSS.")
    
    db = (b'\x00' * ps_len) + b'\x01' + salt
    db_mask = mgf1(h, k - h_len - 1)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    
    masked_db_list = bytearray(masked_db)
    
    # CORREÇÃO: Calcula a máscara exata para limpar os bits excedentes
    bits_to_clear = 8 * k - em_bits
    masked_db_list[0] &= (0xFF >> bits_to_clear)
    
    return bytes(masked_db_list) + h + b'\xbc'

def assinar_pss(conteudo_ficheiro: bytes, chave_privada: tuple[int, int]) -> str:
    n, d = chave_privada
    mod_bits = n.bit_length()
    k = (mod_bits + 7) // 8
    
    # Passamos o mod_bits para o encoder saber o tamanho exato da chave
    em = pss_encode(conteudo_ficheiro, mod_bits) 
    
    m_int = int.from_bytes(em, byteorder='big')
    s_int = pow(m_int, d, n)
    assinatura_bytes = s_int.to_bytes(k, byteorder='big')
    return base64.b64encode(assinatura_bytes).decode('utf-8')

def verificar_pss(conteudo_ficheiro: bytes, assinatura_base64: str, chave_publica: tuple[int, int]) -> bool:
    n, e = chave_publica
    mod_bits = n.bit_length()
    k = (mod_bits + 7) // 8
    em_bits = mod_bits - 1
    h_len = 32
    s_len = 32
    
    try:
        assinatura_bytes = base64.b64decode(assinatura_base64)
    except Exception:
        return False

    if len(assinatura_bytes) != k:
        return False

    s_int = int.from_bytes(assinatura_bytes, byteorder='big')
    if s_int >= n:
        return False
        
    m_int = pow(s_int, e, n)
    em = m_int.to_bytes(k, byteorder='big')

    if em[-1] != 0xbc:
        return False
        
    masked_db = em[:k - h_len - 1]
    h = em[k - h_len - 1 : -1]

    # CORREÇÃO: Verifica a máscara dinâmica dos bits mais significativos
    bits_to_clear = 8 * k - em_bits
    mask = 0xFF >> bits_to_clear
    if (masked_db[0] & ~mask) != 0:
        return False

    db_mask = mgf1(h, k - h_len - 1)
    db = bytearray(x ^ y for x, y in zip(masked_db, db_mask))
    
    # CORREÇÃO: Zera os mesmos bits excedentes no 'db' recuperado
    db[0] &= mask 

    ps_len = k - s_len - h_len - 2
    for i in range(ps_len):
        if db[i] != 0x00:
            return False
            
    if db[ps_len] != 0x01:
        return False

    salt = db[-s_len:]
    m_hash = sha3_256(conteudo_ficheiro)
    m_linha = (b'\x00' * 8) + m_hash + salt
    h_linha = sha3_256(m_linha)

    return h == h_linha

# ==========================================================
# EXECUÇÃO GERAL E TESTES
# ==========================================================
if __name__ == "__main__":
    print("="*50)
    print("INICIANDO SISTEMA DE SEGURANÇA RSA")
    print("="*50)
    
    print("\n[Parte I] Gerando chaves RSA de 2048 bits (Aguarde...).")
    p = get_prime(1024, 10)
    q = get_prime(1024, 10)
    n = p * q
    phi = get_phi(p, q)
    e = find_e(phi)
    d = mod_inverso(e, phi)
    
    chave_publica = (n, e)
    chave_privada = (n, d)
    print("Chaves geradas com sucesso!\n")

    # --- Testando a Exportação e Importação ---
    print("[Parte I - Extra] Testando exportacao e importacao de chaves...")
    
    # 1. Exporta para arquivos físicos
    exportar_chave(chave_publica, "publica", "chave_pub.json")
    exportar_chave(chave_privada, "privada", "chave_priv.json")
    print(" -> Chaves exportadas para 'chave_pub.json' e 'chave_priv.json'.")
    
    # 2. Importa dos arquivos para novas variáveis
    chave_publica = importar_chave("chave_pub.json")
    chave_privada = importar_chave("chave_priv.json")
    print(" -> Chaves importadas com sucesso a partir dos arquivos.\n")
    
    # --------------------------------------------------------
    print("[Parte II] Teste de Cifragem RSA-OAEP")
    msg_secreta = "Esta mensagem utiliza padding probabilistico OAEP."
    cifrado = cifrar_oaep(msg_secreta, chave_publica)
    print(f"Mensagem cifrada (parcial): {str(cifrado)[:30]}...")
    
    decifrado = decifrar_oaep(cifrado, chave_privada)
    print(f"Mensagem decifrada e verificada: '{decifrado}'\n")
    
    # --------------------------------------------------------
    print("[Parte III e IV] Testes de Assinatura e Verificacao (RSA-PSS)")
    documento = b"Relatorio final de trabalho. Criptografia aprovada!"
    
    # Assina
    assinatura = assinar_pss(documento, chave_privada)
    print(f"Assinatura em Base64: {assinatura[:40]}...\n")
    
    # Teste 1: Caminho Feliz
    print("(A) Teste de Ficheiro Integro:")
    valido = verificar_pss(documento, assinatura, chave_publica)
    print("   ->", "SUCESSO: Assinatura VALIDA e arquivo integro." if valido else "FALHA")
    
    # Teste 2: Alteração de Ficheiro
    print("\n(B) Teste alterando UM byte do ficheiro:")
    doc_adulterado = b"Relatorio final de trabalho. Criptografia reprovada!"
    valido2 = verificar_pss(doc_adulterado, assinatura, chave_publica)
    print("   ->", "ERRO: Assinatura reportada valida!" if valido2 else "SUCESSO: Adulteração detectada. Assinatura INVALIDA.")
    
    # Teste 3: Alteração da Assinatura
    print("\n(C) Teste alterando UM byte da assinatura Base64:")
    ass_adulterada = assinatura[:-3] + ('A' if assinatura[-2] != 'A' else 'B') + assinatura[-2:]
    valido3 = verificar_pss(documento, ass_adulterada, chave_publica)
    print("   ->", "ERRO: Assinatura reportada valida!" if valido3 else "SUCESSO: Adulteração detectada. Assinatura INVALIDA.")
    
    # Teste 4: Chave Pública Incorreta
    print("\n(D) Teste verificando com chave publica incorreta:")
    chave_pub_falsa = (n, 65539) # Expoente diferente
    valido4 = verificar_pss(documento, assinatura, chave_pub_falsa)
    print("   ->", "ERRO: Assinatura reportada valida!" if valido4 else "SUCESSO: Adulteração detectada. Assinatura INVALIDA.")
