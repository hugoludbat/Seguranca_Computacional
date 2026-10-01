# CIC0201 - Segurança Computacional - 2026/2
## Trabalho de Implementação 2: Sistema de Assinatura Digital e Verificação Segura de Arquivos

### Equipe
* **Henrique Marques Romeiro França** (Matrícula: 242039130)
* **Lucas Silva Carneiro** (Matrícula: 211026655)
* **Hugo Ludwig Ramos Batista** (Matrícula: 190014415)
* **Luiz Augusto Araujo da Silva** (Matrícula: 211036105)

---

### Visão Geral
Este projeto implementa os principais componentes criptográficos de um sistema moderno baseado no algoritmo **RSA** operando com chaves de no mínimo 2048 bits. O sistema distingue claramente o uso do RSA para duas finalidades:
1. **Cifragem e Decifragem** de mensagens curtas utilizando o esquema de padding probabilístico **RSA-OAEP**.
2. **Assinatura Digital e Verificação** de integridade de arquivos estruturados utilizando o esquema **RSA-PSS**.

A implementação não utiliza bibliotecas criptográficas de alto nível (como OpenSSL) para a matemática central, geração de chaves ou lógicas de padding. O resumo criptográfico (SHA3-256) foi implementado utilizando o pacote nativo `hashlib` do Python, conforme as permissões das diretrizes do trabalho.

### Funcionalidades Implementadas
* **Geração de Chaves RSA:** Teste de primalidade Miller-Rabin, geração de chaves de 2048 bits e cálculo nativo do inverso modular.
* **Gerenciamento de Arquivos:** Exportação e importação de chaves criptográficas em formato estruturado JSON.
* **RSA-OAEP:** Cifragem probabilística utilizando MGF1 e SHA3-256 nativos, prevenindo ataques de maleabilidade e analisando falhas no *padding*.
* **RSA-PSS (RFC 8017):** Assinatura digital robusta utilizando *salt*, prevenindo a simplificação insegura de "cifragem do hash".
* **Empacotamento Seguro:** Geração de um contêiner JSON (`arquivo_assinado.json`) que unifica payload, cifra, assinatura e as chaves utilizadas para facilitar a auditoria do arquivo.
* **Validador de Integridade:** Rotina automatizada que verifica fatores primos, compatibilidade de resumos criptográficos (SHA3-256) e a autenticidade via PSS.

---

### Requisitos e Dependências
O sistema foi desenvolvido utilizando as bibliotecas padrão do interpretador Python, não sendo necessária a instalação de pacotes externos (`pip install`).
* **Linguagem:** Python 3.8+
* **Bibliotecas utilizadas:** `os`, `base64`, `hashlib`, `random`, `json`

---

### Instruções de Execução

Para executar o programa e a suíte completa de testes, basta rodar o arquivo principal pelo terminal no diretório do projeto:

```bash
python T2-Final-com-testes.py
```

### Casos de Teste Inclusos
Durante a execução, o programa passará pelas seguintes fases automaticamente, apresentando os resultados no terminal:

1. **Geração e Persistência de Chaves:** 
   * Gera o par RSA de 2048 bits e os exporta para `chave_pub.json` e `chave_priv.json`, importando-os em seguida.
2. **Teste Cifragem (RSA-OAEP):** 
   * Cifra uma mensagem de teste e a decifra, garantindo a exatidão do processo.
3. **Testes de Assinatura (RSA-PSS):**
   * **(A) Ficheiro Íntegro:** Validação no caminho feliz.
   * **(B) Alteração de 1 Byte no Ficheiro:** Modificação do *payload* do texto em memória.
   * **(C) Alteração de 1 Byte na Assinatura:** Modificação do *output* Base64 da assinatura gerada.
   * **(D) Chave Pública Falsa:** Inserção de um expoente público incorreto (`65539` em vez de `65537`).
4. **Testes Funcionais com Arquivo JSON:**
   * Gera o arquivo estruturado `arquivo_assinado.json` com base no `documento_teste.txt`.
   * Realiza o *parsing* completo desse JSON e valida 4 etapas (Primos, Hash, PSS e Integridade Geral).
   * **Adulteração Estrutural Avançada:** O script altera maliciosamente o payload Base64 injetando um erro proposital e salva como `arquivo_adulterado.json`. Em seguida, roda a verificação que deve acusar a adulteração (falha na etapa do Hash e do PSS).