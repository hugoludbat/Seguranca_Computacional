# Universidade de Brasilia 2026 - Seguranca Computacional
# Trabalho 2 - Sistema de Assinatura Digital e Verificação Segura de Arquivos
# Implementação unificada: RSA, OAEP e PSS

import os
import base64
import hashlib
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
        output += hashlib.sha3_256(seed + c).digest()
        counter += 1
    return output[:length]

# ==========================================================
# PARTE II - CIFRAGEM E DECIFRAGEM RSA-OAEP
# ==========================================================

def oaep_encode(mensagem_bytes: bytes, k: int, label: bytes = b"") -> bytes:
    h_len = 32 # SHA3-256 length
    if len(mensagem_bytes) > k - 2 * h_len - 2:
        raise ValueError("Mensagem muito longa para o tamanho da chave RSA.")
    
    l_hash = hashlib.sha3_256(label).digest()
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
    l_hash = hashlib.sha3_256(label).digest()
    
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
    
    m_hash = hashlib.sha3_256(mensagem_bytes).digest()
    salt = os.urandom(s_len)
    m_linha = (b'\x00' * 8) + m_hash + salt
    h = hashlib.sha3_256(m_linha).digest()
    
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
    m_hash = hashlib.sha3_256(conteudo_ficheiro).digest()
    m_linha = (b'\x00' * 8) + m_hash + salt
    h_linha = hashlib.sha3_256(m_linha).digest()

    return h == h_linha


# ==========================================================
# FUNÇÕES DE TESTE - ASSINATURA DIGITAL E VERIFICAÇÃO
# ==========================================================

def gerar_arquivo_assinado(caminho_arquivo: str,
                           chave_privada: tuple[int, int],
                           chave_publica: tuple[int, int],
                           p: int,
                           q: int,
                           nome_saida: str = "arquivo_assinado.json") -> bool:
    """
    Função de teste: Gera um arquivo contendo:
    - Chave pública (n, e)
    - Chave privada (n, d)
    - Números primos usados (p, q)
    - Plaintext (conteúdo original do arquivo)
    - Ciphertext (mensagem cifrada com OAEP)
    - Assinatura digital (PSS)
    - Hash da assinatura para verificação adicional

    Retorna True se bem-sucedido, False caso contrário.
    """
    try:
        # Lê o conteúdo do arquivo original
        with open(caminho_arquivo, 'rb') as f:
            plaintext = f.read()

        # Cifra o conteúdo usando RSA-OAEP
        # Converte bytes para string para cifrar
        plaintext_str = plaintext.decode('utf-8', errors='replace')
        ciphertext = cifrar_oaep(plaintext_str, chave_publica)

        # Assina digitalmente o arquivo usando RSA-PSS
        assinatura = assinar_pss(plaintext, chave_privada)

        # Extrai componentes das chaves
        n_pub, e = chave_publica
        n_priv, d = chave_privada

        # Cria estrutura JSON com todos os dados
        dados_arquivo = {
            "metadados": {
                "descricao": "Arquivo assinado digitalmente com RSA-PSS",
                "tipo_assinatura": "RSA-PSS com SHA3-256",
                "tipo_cifragem": "RSA-OAEP com SHA3-256",
                "tamanho_chave_bits": n_pub.bit_length(),
                "data_geracao": str(__import__('datetime').datetime.now())
            },
            "chaves": {
                "publica": {
                    "n": n_pub,
                    "e": e
                },
                "privada": {
                    "n": n_priv,
                    "d": d
                }
            },
            "numeros_primos": {
                "p": p,
                "q": q,
                "n_produto": n_pub
            },
            "conteudo": {
                "plaintext_base64": base64.b64encode(plaintext).decode('utf-8'),
                "ciphertext": str(ciphertext),
                "tamanho_original_bytes": len(plaintext)
            },
            "assinatura_digital": {
                "valor_base64": assinatura,
                "tamanho_bytes": len(base64.b64decode(assinatura)),
                "hash_sha3_256": hashlib.sha3_256(plaintext).hexdigest()
            }
        }

        # Salva a estrutura em arquivo JSON
        with open(nome_saida, 'w') as f:
            json.dump(dados_arquivo, f, indent=4)

        print(f"  Arquivo assinado gerado com sucesso: '{nome_saida}'")
        print(f"  - Plaintext: {len(plaintext)} bytes")
        print(f"  - Tamanho da chave: {n_pub.bit_length()} bits")
        print(f"  - Assinatura válida e armazenada")

        return True

    except FileNotFoundError:
        print(f" Erro: Arquivo '{caminho_arquivo}' não encontrado.")
        return False
    except Exception as e:
        print(f" Erro ao gerar arquivo assinado: {str(e)}")
        return False


def verificar_integridade_arquivo(caminho_arquivo_assinado: str) -> bool:
    """
    Função de teste de integridade: Verifica a integridade da assinatura digital de um arquivo
    gerado pela Função de geração de arquivo.

    Realiza as seguintes verificações:
    - Carrega o arquivo JSON
    - Extrai a chave pública e o conteúdo original
    - Valida a assinatura PSS contra o plaintext
    - Verifica se os números primos (p, q) multiplicam-se corretamente para gerar n
    - Valida o hash SHA3-256 do conteúdo

    Retorna True se a assinatura é válida e o arquivo está íntegro, False caso contrário.
    """
    try:
        # Carrega o arquivo JSON
        with open(caminho_arquivo_assinado, 'r') as f:
            dados = json.load(f)

        print(f"\n{'=' * 60}")
        print(f" VERIFICAÇÃO DE INTEGRIDADE - {caminho_arquivo_assinado}")
        print(f"{'=' * 60}")

        # Extrai os componentes
        chave_publica = (dados["chaves"]["publica"]["n"],
                         dados["chaves"]["publica"]["e"])

        plaintext_b64 = dados["conteudo"]["plaintext_base64"]
        plaintext = base64.b64decode(plaintext_b64)

        assinatura_b64 = dados["assinatura_digital"]["valor_base64"]
        hash_armazenado = dados["assinatura_digital"]["hash_sha3_256"]

        p = dados["numeros_primos"]["p"]
        q = dados["numeros_primos"]["q"]
        n = dados["chaves"]["publica"]["n"]

        # --- VERIFICAÇÃO 1: Validação dos números primos ---
        print("\n[Verificação 1] Validando números primos p e q...")
        if p * q == n:
            print(f"   p × q = n == {hex(p)[:16]}... x {hex(q)[:16]}... = {hex(n)[:16]}... (Números primos válidos)")
        else:
            print(f"   FALHA: p × q ≠ n")
            print(f"    p × q = {p * q}")
            print(f"    n    = {n}")
            return False

        # --- VERIFICAÇÃO 2: Hash SHA3-256 do conteúdo ---
        print("\n[Verificação 2] Validando hash SHA3-256 do plaintext...")
        hash_calculado = hashlib.sha3_256(plaintext).hexdigest()
        if hash_calculado == hash_armazenado:
            print(f"   Hash corresponde(hash_calculado) : {hash_calculado[:32]}...")
            print(f"   Hash corresponde(hash_armazenado): {hash_armazenado[:32]}...")
        else:
            print(f"   FALHA: Hash não corresponde!")
            print(f"    Armazenado: {hash_armazenado}")
            print(f"    Calculado:  {hash_calculado}")
            return False

        # --- VERIFICAÇÃO 3: Assinatura Digital (RSA-PSS) ---
        print("\n[Verificação 3] Validando assinatura digital RSA-PSS...")
        assinatura_valida = verificar_pss(plaintext, assinatura_b64, chave_publica)

        if assinatura_valida:
            print("   Assinatura digital VÁLIDA")
            print(f"    Método: RSA-PSS com SHA3-256")
            print(f"    Tamanho da chave: {chave_publica[0].bit_length()} bits")
        else:
            print("   FALHA: Assinatura digital INVÁLIDA!")
            print("    O arquivo foi adulterado ou a assinatura foi modificada.")
            return False

        # --- VERIFICAÇÃO 4: Integridade geral ---
        print("\n[Verificação 4] Resumo de Integridade...")
        print(f"   Arquivo carregado com sucesso")
        print(f"   Tamanho do conteúdo original: {len(plaintext)} bytes")
        print(f"   Ciphertext armazenado: {dados['conteudo']['ciphertext'][:40]}...")
        print(f"   Todas as verificações passaram!")

        print(f"\n{'=' * 60}")
        print("RESULTADO FINAL: ARQUIVO ÍNTEGRO E AUTÊNTICO")
        print(f"{'=' * 60}\n")

        return True

    except FileNotFoundError:
        print(f" Erro: Arquivo '{caminho_arquivo_assinado}' não encontrado.")
        return False
    except json.JSONDecodeError:
        print(f" Erro: Arquivo não é um JSON válido.")
        return False
    except KeyError as e:
        print(f" Erro: Campo esperado não encontrado no arquivo: {str(e)}")
        return False
    except Exception as e:
        print(f" Erro ao verificar integridade: {str(e)}")
        return False


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
    msg_secreta = "The quick brown fox jumps over the lazy dog Esta mensagem utiliza padding probabilistico OAEP."
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

    # Rodada de testes funcionais

    print("\n" + "=" * 60)
    print("TESTES FUNCIONAIS")
    print("=" * 60)

    # Cria um arquivo de teste
    arquivo_teste = "documento_teste.txt"
    with open(arquivo_teste, 'w') as f:
        f.write("Relatorio final de trabalho. Criptografia aprovada!")

    # ========== TESTE FUNCIONAL 1: Gerar arquivo assinado ==========
    print("\n[Função 1] Gerando arquivo com assinatura digital...")
    sucesso = gerar_arquivo_assinado(
        caminho_arquivo=arquivo_teste,
        chave_privada=chave_privada,
        chave_publica=chave_publica,
        p=p,
        q=q,
        nome_saida="arquivo_assinado.json"
    )

    if sucesso:
        # ========== FUNÇÃO 2: Verificar integridade ==========
        print("\n[Função 2] Verificando integridade do arquivo assinado...")
        integridade_ok = verificar_integridade_arquivo("arquivo_assinado.json")

        # Teste adicional: Tentar verificar com arquivo adulterado
        print("\n[Teste Adicional] Adulterando o arquivo e tentando verificar...")
        with open("arquivo_assinado.json", 'r') as f:
            dados_adulterado = json.load(f)

        # Adultera o plaintext
        plaintext_orig = base64.b64decode(dados_adulterado["conteudo"]["plaintext_base64"])
        plaintext_novo = plaintext_orig.replace(b"aprovada", b"reprovada")
        dados_adulterado["conteudo"]["plaintext_base64"] = base64.b64encode(plaintext_novo).decode()

        with open("arquivo_adulterado.json", 'w') as f:
            json.dump(dados_adulterado, f, indent=4)

        print("Arquivo adulterado salvo como 'arquivo_adulterado.json'")
        resultado_adulterado = verificar_integridade_arquivo("arquivo_adulterado.json")

        print(
            f"\nResultado: {'FALHA detectada com sucesso!' if not resultado_adulterado else 'ERRO: Falha não foi detectada!'}")

