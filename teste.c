#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// Estrutura de um bloco
typedef struct Block {
    int index;               // Índice do bloco na cadeia
    char previous_hash[65];  // Hash do bloco anterior
    char merkle_root[65];    // Raiz da Merkle Tree
    char data[256];          // Dados armazenados no bloco
    char hash[65];           // Hash atual do bloco
    int nonce;               // Número usado para a prova de trabalho
    time_t timestamp;        // Timestamp da criação do bloco
    struct Block *next;      // Ponteiro para o próximo bloco
} Block;

// Função para calcular o hash SHA-256
void calculate_hash(Block *block, char *output) {
    char input[512];
    snprintf(input, sizeof(input), "%d%s%s%d%ld%s", block->index, block->previous_hash,
             block->data, block->nonce, block->timestamp, block->merkle_root);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)input, strlen(input), hash);

    // Converte o hash para uma string hexadecimal
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';  // Finaliza a string com caractere nulo
}

// Função para calcular o hash de uma transação ou dados
void calculate_transaction_hash(const char *data, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)data, strlen(data), hash);

    // Converte o hash para uma string hexadecimal
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';  // Finaliza a string com caractere nulo
}

// Função para construir a Merkle Tree e retornar a raiz
void build_merkle_tree(char transactions[][256], int num_transactions,
                       char *merkle_root) {
    char hashes[num_transactions][65];

    // Calcula os hashes das transações
    for (int i = 0; i < num_transactions; i++) {
        calculate_transaction_hash(transactions[i], hashes[i]);
    }

    // Combina os hashes até obter um único hash
    while (num_transactions > 1) {
        int j = 0;
        for (int i = 0; i < num_transactions; i += 2) {
            if (i + 1 < num_transactions) {
                char combined[512];
                snprintf(combined, sizeof(combined), "%s%s", hashes[i], hashes[i + 1]);
                calculate_transaction_hash(combined, hashes[j]);
            } else {
                strcpy(hashes[j], hashes[i]);
            }
            j++;
        }
        num_transactions = j;
    }

    // A raiz da Merkle Tree
    strcpy(merkle_root, hashes[0]);
}

// Função para realizar a prova de trabalho
void proof_of_work(Block *block, int difficulty) {
    char prefix[65] = {0};
    memset(prefix, '0', difficulty);  // Cria um prefixo com 'difficulty' zeros

    printf("Iniciando prova de trabalho para o bloco %d...\n", block->index);

    do {
        block->nonce++;
        calculate_hash(block, block->hash);
        printf("Tentando nonce %d: %s\n", block->nonce, block->hash);
    } while (strncmp(block->hash, prefix, difficulty) != 0);

    printf("Prova de trabalho concluída para o bloco %d! Nonce: %d\n", block->index,
           block->nonce);
}

// Função para criar um bloco
Block *create_block(int index, const char *previous_hash, const char *data[],
                    int num_transactions, int difficulty) {
    Block *block = (Block *)malloc(sizeof(Block));
    block->index = index;
    strncpy(block->previous_hash, previous_hash, 65);

    // Criar a Merkle Tree e obter a raiz
    build_merkle_tree((char(*)[256])data, num_transactions, block->merkle_root);

    // Definir os dados do bloco (por exemplo, "transactions")
    snprintf(block->data, sizeof(block->data), "Transações");

    block->nonce = 0;
    block->timestamp = time(NULL);

    // Realiza a prova de trabalho para encontrar um hash válido
    proof_of_work(block, difficulty);

    block->next = NULL;
    return block;
}

// Função para criar o bloco gênesis
Block *create_genesis_block(int difficulty) {
    printf("Criando bloco gênesis...\n");
    return create_block(0, "0", NULL, 0, difficulty);
}

// Função para adicionar um bloco à cadeia
void add_block(Block **blockchain, const char *data[], int num_transactions,
               int difficulty) {
    Block *last_block = *blockchain;

    while (last_block->next != NULL) {
        last_block = last_block->next;
    }

    Block *new_block = create_block(last_block->index + 1, last_block->hash, data,
                                    num_transactions, difficulty);
    last_block->next = new_block;
}

// Função para imprimir toda a cadeia
void print_blockchain(Block *blockchain) {
    Block *current = blockchain;

    while (current != NULL) {
        printf("Bloco %d\n", current->index);
        printf("Timestamp: %s", ctime(&current->timestamp));
        printf("Hash anterior: %s\n", current->previous_hash);
        printf("Raiz da Merkle: %s\n", current->merkle_root);
        printf("Dados: %s\n", current->data);
        printf("Hash: %s\n", current->hash);
        printf("Nonce: %d\n\n", current->nonce);
        current = current->next;
    }
}

// Função para validar a blockchain
int validar(Block *blockchain) {
    Block *current = blockchain;

    if (current == NULL) {
        printf("Blockchain está vazia!\n");
        return 0;
    }

    if (strncmp(current->previous_hash, "0", 64) != 0) {
        printf("Falha na validação! O hash anterior do bloco gênesis está incorreto.\n");
        return 0;
    }

    while (current != NULL && current->next != NULL) {
        if (strncmp(current->hash, current->next->previous_hash, 64) != 0) {
            printf(
                "Falha na validação! A cadeia está corrompida entre os blocos %d e %d.\n",
                current->index, current->next->index);
            return 0;
        }

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

// Função para exibir o menu e interagir com o usuário
void display_menu() {
    printf("\n--- Blockchain Menu ---\n");
    printf("1. Criar bloco gênesis\n");
    printf("2. Adicionar um novo bloco\n");
    printf("3. Exibir blockchain completa\n");
    printf("4. Sair\n");
    printf("5. Validar a blockchain\n");
    printf("Escolha uma opção: ");
}

// Função principal
int main() {
    int difficulty = 2;  // Número de zeros exigidos no hash
    Block *blockchain = NULL;
    int option;
    char data[256];
    int num_transactions = 2;
    const char *transactions[] = {"Transação 1", "Transação 2"};

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
                    printf("Adicionando um novo bloco...\n");
                    add_block(&blockchain, transactions, num_transactions, difficulty);
                    printf("Novo bloco adicionado com sucesso!\n");
                } else {
                    printf("O bloco gênesis deve ser criado primeiro!\n");
                }
                break;

            case 3:
                if (blockchain != NULL) {
                    print_blockchain(blockchain);
                } else {
                    printf("Nenhuma blockchain foi criada ainda.\n");
                }
                break;

            case 4:
                printf("Saindo...\n");
                break;

            case 5:
                if (blockchain != NULL) {
                    validar(blockchain);
                } else {
                    printf("Blockchain está vazia!\n");
                }
                break;

            default:
                printf("Opção inválida! Tente novamente.\n");
                break;
        }
    } while (option != 4);

    return 0;
}
