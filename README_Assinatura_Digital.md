# Sistema de Assinatura Digital e Verificação Segura de Arquivos

**Universidade de Brasília (UnB)**
**Disciplina:** CIC0201 - Segurança Computacional (2026/2)
**Professora:** Priscila Solis Barreto

## Integrantes do Grupo
* Henrique Marques Romeiro França (Matrícula: 242039130)
* Lucas Silva Carneiro (Matrícula: 211026655)
* Hugo Ludwig Ramos Batista (Matrícula: 190014415)
* Luiz Augusto Araujo da Silva (Matrícula: 211036105)

## Descrição do Projeto
Este projeto consiste na implementação nativa em Python dos principais componentes criptográficos de um sistema moderno baseado em RSA. Atendendo aos requisitos da disciplina, a lógica central (geração de chaves, testes de primalidade, operações RSA, OAEP, PSS e MGF1) foi desenvolvida do zero, sem o auxílio de bibliotecas criptográficas de terceiros como o OpenSSL. Apenas bibliotecas padrão do Python foram utilizadas.

O código-fonte unificado encontra-se no arquivo `T2-Completo.py`.

## Pré-requisitos
* **Python 3.x** instalado na máquina.
* Nenhuma biblioteca externa (`pip install`) é necessária. O script utiliza apenas módulos nativos (`os`, `base64`, `random`, `json`).

## Instruções de Execução
Para executar o sistema e rodar a bateria de testes, abra o terminal na pasta onde o arquivo se encontra e execute o seguinte comando:

```bash
python T2-Completo.py
```
*(Nota: dependendo da configuração do seu sistema operacional, pode ser necessário utilizar `python3`).*

Ao ser executado, o programa criará dois arquivos na mesma pasta: `chave_pub.json` e `chave_priv.json`, que demonstram a funcionalidade de exportação e persistência das chaves geradas.

## Casos de Teste Abordados
O script principal está configurado para executar automaticamente e de forma sequencial os seguintes testes estruturais:

1. **Parte I - Geração de Chaves:** 
   * Geração de primos com Miller-Rabin.
   * Criação de par de chaves RSA de 2048 bits.
   * Exportação para JSON e importação bem-sucedida das chaves na memória.
2. **Parte II - Cifragem RSA-OAEP:**
   * Cifragem de uma mensagem curta em texto claro.
   * Decifragem e recuperação correta do preenchimento e da mensagem.
3. **Partes III e IV - Assinatura Digital e Verificação (RSA-PSS):**
   * Geração da assinatura codificada em Base64 para um arquivo de texto simulado.
   * **Teste A (Caminho Feliz):** Verificação de integridade confirmando a validade da assinatura com o documento original e a chave pública correta.
   * **Teste B (Adulteração do Arquivo):** Detecção de fraude ao alterar um byte do documento original.
   * **Teste C (Adulteração da Assinatura):** Detecção de fraude ao corromper um caractere da string Base64 da assinatura.
   * **Teste D (Chave Pública Incorreta):** Bloqueio da verificação ao tentar utilizar uma chave com um expoente forjado/inválido.