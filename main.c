#include <openssl/sha.h>  // Biblioteca para funções de hash SHA-256
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>  // Inclui a função sleep para simular atraso

// Estrutura de um bloco
typedef struct Block {
    int index;               // Índice do bloco na cadeia
    char previous_hash[65];  // Hash do bloco anterior
    char data[256];          // Dados armazenados no bloco
    char hash[65];           // Hash atual do bloco
    int nonce;               // Número usado para a prova de trabalho
    time_t timestamp;        // Timestamp da criação do bloco
    struct Block *next;      // Ponteiro para o próximo bloco
} Block;

// Função para calcular o hash SHA-256
void calculate_hash(Block *block, char *output) {
    char input[512];
    snprintf(input, sizeof(input), "%d%s%s%d%ld", block->index, block->previous_hash,
             block->data, block->nonce, block->timestamp);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)input, strlen(input), hash);

    // Converte o hash para uma string hexadecimal
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';  // Finaliza a string com caractere nulo
}

// Função para realizar a prova de trabalho
void proof_of_work(Block *block, int difficulty) {
    char prefix[65] = {0};
    memset(prefix, '0', difficulty);  // Cria um prefixo com 'difficulty' zeros

    printf("Iniciando prova de trabalho para o bloco %d...\n", block->index);

    do {
        block->nonce++;
        calculate_hash(block, block->hash);
        printf("Tentando nonce %d: %s\n", block->nonce,
               block->hash);  // Print de cada tentativa
    } while (strncmp(block->hash, prefix, difficulty) != 0);

    printf("Prova de trabalho concluída para o bloco %d! Nonce: %d\n", block->index,
           block->nonce);
}

// Função para criar um bloco
Block *create_block(int index, const char *previous_hash, const char *data,
                    int difficulty) {
    Block *block = (Block *)malloc(sizeof(Block));
    block->index = index;
    strncpy(block->previous_hash, previous_hash, 65);
    strncpy(block->data, data, 256);
    block->nonce = 0;
    block->timestamp = time(NULL);  // Define o timestamp inicial do bloco

    // Realiza a prova de trabalho para encontrar um hash válido
    proof_of_work(block, difficulty);

    block->next = NULL;
    return block;
}

// Função para criar o bloco gênesis
Block *create_genesis_block(int difficulty) {
    printf("Criando bloco gênesis...\n");
    return create_block(0, "0", "Genesis Block", difficulty);
}

// Função para adicionar um bloco à cadeia
void add_block(Block **blockchain, const char *data, int difficulty) {
    Block *last_block = *blockchain;

    // Percorre a cadeia até o último bloco
    while (last_block->next != NULL) {
        last_block = last_block->next;
    }

    // Cria um novo bloco e adiciona à cadeia
    Block *new_block =
        create_block(last_block->index + 1, last_block->hash, data, difficulty);
    last_block->next = new_block;
}

// Função para imprimir toda a cadeia

void print_blockchain(Block *blockchain) {
    Block *current = blockchain;

    while (current != NULL) {
        printf("Bloco %d\n", current->index);
        printf("Timestamp: %s",
               ctime(&current->timestamp));  // Exibe o timestamp formatado
        printf("Hash anterior: %s\n", current->previous_hash);
        printf("Dados: %s\n", current->data);
        printf("Hash: %s\n", current->hash);
        printf("Nonce: %d\n\n", current->nonce);
        current = current->next;
    }
}

// Função para validar a blockchain

int validar(Block *blockchain) {
    Block *current = blockchain;

    // Verifica se a cadeia tem pelo menos um bloco (bloco gênesis)
    if (current == NULL) {
        printf("Blockchain está vazia!\n");
        return 0;
    }

    // Validação do bloco gênesis (hash anterior do bloco gênesis deve ser "0")
    if (strncmp(current->previous_hash, "0", 64) != 0) {
        printf("Falha na validação! O hash anterior do bloco gênesis está incorreto.\n");
        return 0;
    }

    // Valida todos os blocos na cadeia
    while (current != NULL && current->next != NULL) {
        // Verifica se o hash do bloco atual corresponde ao hash do bloco anterior do
        // próximo bloco
        if (strncmp(current->hash, current->next->previous_hash, 64) != 0) {
            printf(
                "Falha na validação! A cadeia está corrompida entre os blocos %d e %d.\n",
                current->index, current->next->index);
            return 0;
        }

        // Verifica se o hash do bloco atual é válido
        char calculated_hash[65];
        calculate_hash(current, calculated_hash);
        if (strncmp(current->hash, calculated_hash, 64) != 0) {
            printf("Falha na validação! O hash do bloco %d está incorreto.\n",
                   current->index);
            return 0;
        }

        current = current->next;
    }

    printf("Blockchain válida!\n");
    return 1;
}

// Função para modificar um bloco (simulando um ataque)
// Função para modificar um bloco (simulando um ataque)
void modificar_bloco(Block *blockchain, int index, const char *new_data) {
    // Modificar os dados do bloco
    Block *current = blockchain;
    int count = 0;
    while (current != NULL) {
        if (count == index) {
            snprintf(current->data, sizeof(current->data), "%s", new_data);
            printf("Bloco %d modificado: %s\n", index, current->data);

            // Recalcular o hash do bloco modificado
            calculate_hash(current, current->hash);

            // Recalcular os hashes dos blocos seguintes
            Block *next_block = current->next;
            while (next_block != NULL) {
                calculate_hash(next_block, next_block->hash);
                next_block = next_block->next;
            }
            return;
        }
        current = current->next;
        count++;
    }
    printf("Índice do bloco inválido!\n");
}

// Função para exibir o menu e interagir com o usuário
void display_menu() {
    printf("\n--- Blockchain Menu ---\n");
    printf("1. Criar bloco gênesis\n");
    printf("2. Adicionar um novo bloco\n");
    printf("3. Exibir blockchain completa\n");
    printf("4. Sair\n");
    printf("5. Validar a blockchain\n");
    printf("6. Modificar um bloco (simulando ataque)\n");

    printf("Escolha uma opção: ");
}

// Função principal
int main() {
    int difficulty = 3;  // Número de zeros iniciais exigidos no hash
    Block *blockchain = NULL;
    int option;
    char data[256];
    int index;

    do {
        display_menu();
        scanf("%d", &option);
        getchar();  // Limpa o buffer de entrada

        switch (option) {
            case 1:
                if (blockchain == NULL) {
                    blockchain = create_genesis_block(difficulty);
                    printf("Bloco gênesis criado com sucesso!\n");
                } else {
                    printf("Bloco gênesis já existe!\n");
                }
                break;

            case 2:
                if (blockchain != NULL) {
                    printf("Digite os dados para o novo bloco: ");
                    fgets(data, sizeof(data), stdin);
                    data[strcspn(data, "\n")] = '\0';  // Remove o caractere de nova linha
                    add_block(&blockchain, data, difficulty);
                    printf("Novo bloco adicionado com sucesso!\n");
                } else {
                    printf("Crie o bloco gênesis primeiro!\n");
                }
                break;

            case 3:
                if (blockchain != NULL) {
                    printf("\nExibindo a blockchain completa:\n");
                    print_blockchain(blockchain);
                } else {
                    printf("Blockchain está vazia!\n");
                }
                break;

            case 4:
                printf("Saindo do programa...\n");
                break;

            case 5:
                if (blockchain != NULL) {
                    validar(blockchain);
                } else {
                    printf("Blockchain está vazia!\n");
                }
                break;

            case 6:
                if (blockchain != NULL) {
                    printf("Digite o índice do bloco a ser modificado: ");
                    scanf("%d", &index);
                    getchar();  // Limpa o buffer de entrada
                    printf("Digite os novos dados para o bloco: ");
                    fgets(data, sizeof(data), stdin);
                    data[strcspn(data, "\n")] = '\0';  // Remove o caractere de nova linha
                    modificar_bloco(blockchain, index, data);
                } else {
                    printf("Blockchain está vazia!\n");
                }
                break;

            default:
                printf("Opção inválida. Tente novamente.\n");
        }
    } while (option != 4);

    // Liberação de memória
    Block *current = blockchain;
    while (current != NULL) {
        Block *temp = current;
        current = current->next;
        free(temp);
    }

    return 0;
}
