# Cifra de Vigenère: Implementação e Criptoanálise

Trabalho de Implementação 1 da disciplina de Segurança Computacional (CIC0201) da Universidade de Brasília (UnB).

## Alunos
* Henrique Marques Romeiro França (242039130)
* Lucas Silva Carneiro (211026655)
* Hugo Ludwig Ramos Batista (190014415)
* Luiz Augusto Araujo da Silva (211036105)

## Objetivo
Este projeto implementa a cifra de Vigenère, com funcionalidades de cifração e decifração de textos, além de um sistema de criptoanálise capaz de quebrar criptogramas utilizando métodos estatísticos (Índice de Coincidência e Teste de Qui-quadrado) baseados na frequência de letras nos idiomas Português e Inglês.

## Pré-requisitos
Para executar o programa, você precisa ter instalado na sua máquina:
* **Python 3.x**
O código foi desenvolvido utilizando apenas bibliotecas nativas do Python (`string`, `unicodedata`, `os`), não sendo necessário instalar dependências adicionais via pip(como foi solicitado no trabalho).

## Como Executar

1.  Abra o terminal (ou prompt de comando) na pasta onde o arquivo `vigenere.py` (ou o nome do seu arquivo principal) está salvo.
2.  Execute o seguinte comando:
   
    ```bash
    python vigenere.py
    ```
4.  O programa apresentará um menu interativo no terminal:
    ```
    --- Cifra de Vigenère ---

    Escolha a opção:
    Criptografar (1)
    Descriptografar (2)
    Hack (3)
    >
    ```

## Utilizando as Funcionalidades

### 1. Criptografar
*   Selecione a opção `1`.
*   Digite o **texto claro** que deseja cifrar (acentos, espaços e números serão desconsiderados durante a normalização do texto).
*   Digite a **chave** (senha) de ofuscação.
*   O programa exibirá o texto cifrado gerado e o salvará em um arquivo local chamado `ultimo_texto.txt` para testes rápidos.

### 2. Descriptografar
*   Selecione a opção `2`.
*   Você poderá escolher usar o **texto salvo** (1) da execução anterior ou inserir um **novo texto** cifrado (2).
*   Digite a **chave** correta para decifrar a mensagem.
*   O programa retornará o texto decifrado, revelando a mensagem original em letras maiúsculas.

### 3. Hack (Criptoanálise / Quebra)
*   Selecione a opção `3`.
*   Escolha entre usar um criptograma salvo (1) ou inserir um novo (2).
*   Defina o **idioma esperado** do texto oculto: Português (1) ou Inglês (2). Isso é crucial, pois o ataque carrega a tabela estatística correspondente de frequências de letras.
*   O algoritmo fará uma varredura para chaves de tamanho 1 a 20.
*   **Resultado:** O sistema exibirá o texto claro decifrado pela melhor chave encontrada, além de mostrar uma tabela com as 5 chaves prováveis (Top 5) baseadas na avaliação dos melhores valores de $\chi^2$ (Qui-quadrado) e Índice de Coincidência (IC).
