#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// Estrutura para armazenar uma transação
typedef struct Transaction
{
    char data[256]; // Dados da transação
} Transaction;

// Estrutura de um bloco
typedef struct Block
{
    int index;
    char previous_hash[65];
    char hashroot[65]; // Hash da raiz da Merkle Tree
    char hash[65];     // Hash do bloco (com base na Merkle root e outros dados)
    int nonce;
    time_t timestamp;
    struct Block *next;
    Transaction *transactions; // Transações associadas a este bloco
    int transaction_count;     // Número de transações neste bloco
} Block;

// Função para calcular o hash SHA-256
void calculate_hash(Block *block, char *output)
{
    char input[512];
    snprintf(input, sizeof(input), "%d%s%s%d%ld", block->index, block->previous_hash,
             block->hashroot, block->nonce, block->timestamp);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)input, strlen(input), hash);

    // Converte o hash para uma string hexadecimal
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0'; // Finaliza a string com caractere nulo
}

// Função para calcular o hash de uma transação
void calculate_transaction_hash(Transaction *tx, char *output)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)tx->data, strlen(tx->data), hash);

    // Converte o hash para uma string hexadecimal
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0'; // Finaliza a string com caractere nulo
}

// Função para construir a Merkle Tree e calcular a hash da raiz
void build_merkle_tree(Block *block)
{
    if (block->transaction_count == 0)
    {
        strcpy(block->hashroot, "0");
        return;
    }

    // Calcula os hashes das transações
    char *tx_hashes[block->transaction_count];
    for (int i = 0; i < block->transaction_count; i++)
    {
        tx_hashes[i] = (char *)malloc(65);
        calculate_transaction_hash(&block->transactions[i], tx_hashes[i]);
    }

    // Construção da árvore de Merkle
    int n = block->transaction_count;
    while (n > 1)
    {
        for (int i = 0; i < n / 2; i++)
        {
            char *combined = (char *)malloc(130); // espaço para 2 hashes
            snprintf(combined, 130, "%s%s", tx_hashes[2 * i], tx_hashes[2 * i + 1]);
            free(tx_hashes[i]); // liberar hashes antigos

            tx_hashes[i] = (char *)malloc(65);
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256((unsigned char *)combined, strlen(combined), hash);

            // Converte o hash para uma string hexadecimal
            for (int j = 0; j < SHA256_DIGEST_LENGTH; j++)
            {
                sprintf(tx_hashes[i] + (j * 2), "%02x", hash[j]);
            }

            tx_hashes[i][64] = '\0';

            free(combined);
        }

        if (n % 2 == 1)
        {
            free(tx_hashes[n/2]); // liberar hashes antigos
            tx_hashes[n / 2] = tx_hashes[n - 1];
            n = (n / 2) + 1;
        }
        else
        {
            n = n / 2;
        }
    }

    // O hash da raiz da Merkle Tree é o primeiro hash gerado
    strcpy(block->hashroot, tx_hashes[0]);

    // Libera a memória alocada para os hashes das transações
    for (int i = 0; i < block->transaction_count; i++)
    {
        if(tx_hashes[i] != NULL) {
            free(tx_hashes[i]);
        }

    }
}

// Função para realizar a prova de trabalho
void proof_of_work(Block *block, int difficulty)
{
    char prefix[65] = {0};
    memset(prefix, '0', difficulty); // Cria um prefixo com 'difficulty' zeros

    do
    {
        block->nonce++;
        calculate_hash(block, block->hash);
        // printf("Testando nonce %d\n",block->nonce);
    } while (strncmp(block->hash, prefix, difficulty) != 0);
}

// Função para criar um bloco
Block *create_block(int index, const char *previous_hash, Transaction *transactions, int transaction_count, int difficulty)
{
    Block *block = (Block *)malloc(sizeof(Block));
    block->index = index;
    strncpy(block->previous_hash, previous_hash, 65);
    block->transactions = (Transaction *)malloc(transaction_count * sizeof(Transaction));
    memcpy(block->transactions, transactions, transaction_count * sizeof(Transaction));
    block->transaction_count = transaction_count;
    block->nonce = 0;
    block->timestamp = time(NULL);

    // Construa a Merkle Tree e obtenha o hashroot
    build_merkle_tree(block);

    // Realiza a prova de trabalho para encontrar um hash válido
    proof_of_work(block, difficulty);

    block->next = NULL;
    return block;
}

// Função para criar o bloco gênesis
Block *create_genesis_block(int difficulty)
{
    printf("Criando bloco gênesis...\n");
    return create_block(0, "0", NULL, 0, difficulty);
}

// Função para adicionar um bloco à cadeia
void add_block(Block **blockchain, Transaction *transactions, int transaction_count, int difficulty)
{
    Block *last_block = *blockchain;
    while (last_block->next != NULL)
    {
        last_block = last_block->next;
    }
    Block *new_block = create_block(last_block->index + 1, last_block->hash, transactions, transaction_count, difficulty);
    last_block->next = new_block;
}

// Função para imprimir toda a cadeia
void print_blockchain(Block *blockchain)
{
    Block *current = blockchain;
    while (current != NULL)
    {
        printf("Bloco %d\n", current->index);
        printf("Timestamp: %s", ctime(&current->timestamp));
        printf("Hash anterior: %s\n", current->previous_hash);
        printf("Merkle Root: %s\n", current->hashroot);
        printf("Hash: %s\n", current->hash);
        printf("Nonce: %d\n", current->nonce);
        printf("Transações:\n");
        for (int i = 0; i < current->transaction_count; i++)
        {
            printf("  - %s\n", current->transactions[i].data);
        }
        printf("\n");
        current = current->next;
    }
}
//calculo da merkle sem modificar bloco
void calculate_merkle_root(Block *block, char *output)
{
    if (block->transaction_count == 0)
    {
        strcpy(output, "0");
        return;
    }

    // Calcula os hashes das transações
    char *tx_hashes[block->transaction_count];
    for (int i = 0; i < block->transaction_count; i++)
    {
        tx_hashes[i] = (char *)malloc(65);
        calculate_transaction_hash(&block->transactions[i], tx_hashes[i]);
    }

    // Construção da árvore de Merkle
    int n = block->transaction_count;
    while (n > 1)
    {
        for (int i = 0; i < n / 2; i++)
        {
            char *combined = (char *)malloc(130); // espaço para 2 hashes
            snprintf(combined, 130, "%s%s", tx_hashes[2 * i], tx_hashes[2 * i + 1]);
            tx_hashes[i] = (char *)malloc(65);
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256((unsigned char *)combined, strlen(combined), hash);

            // Converte o hash para uma string hexadecimal
            for (int j = 0; j < SHA256_DIGEST_LENGTH; j++)
            {
                sprintf(tx_hashes[i] + (j * 2), "%02x", hash[j]);
            }
            tx_hashes[i][64] = '\0';

            free(combined);
        }

        if (n % 2 == 1)
        {
            tx_hashes[n / 2] = tx_hashes[n - 1];
            n = (n / 2) + 1;
        }
        else
        {
            n = n / 2;
        }
    }

    // O hash da raiz da Merkle Tree é o primeiro hash gerado
    strcpy(output, tx_hashes[0]);

    // Libera a memória alocada para os hashes das transações
    for (int i = 0; i < block->transaction_count; i++)
    {
        free(tx_hashes[i]);
    }
}

// Função para validar a blockchain
int validar(Block *blockchain)
{
    Block *current = blockchain;
    if (current == NULL)
    {
        printf("Blockchain está vazia!\n");
        return 0;
    }

    // Validação do bloco gênesis
    if (strncmp(current->previous_hash, "0", 64) != 0)
    {
        printf("Falha na validação! O hash anterior do bloco gênesis está incorreto.\n");
        return 0;
    }

    while (current != NULL && current->next != NULL)
    {
        // Verifica se o hash do bloco anterior é o hash anterior do próximo bloco
        if (strncmp(current->hash, current->next->previous_hash, 64) != 0)
        {
            printf("Falha na validação! A cadeia está corrompida entre os blocos %d e %d.\n", current->index, current->next->index);
            return 0;
        }

        // Verifica se o hash calculado do bloco corresponde ao hash armazenado
        char calculated_hash[65];
        calculate_hash(current, calculated_hash);
        if (strncmp(current->hash, calculated_hash, 64) != 0)
        {
            printf("Falha na validação! O hash do bloco %d está incorreto.\n", current->index);
            return 0;
        }

        // Valida a Merkle Root
        char calculated_merkle_root[65];
        calculate_merkle_root(current, calculated_merkle_root);
        if (strncmp(current->hashroot, calculated_merkle_root, 64) != 0 && (current->index != 0))
        {
            printf("Falha na validação! A Merkle Root do bloco %d está incorreta.\n", current->index);
            return 0;
        }

        current = current->next;
    }

    printf("Blockchain válida!\n");
    return 1;
}


void free_blockchain(Block *blockchain)
{
    Block *current = blockchain;
    while (current != NULL)
    {
        Block *temp = current;
        current = current->next;

        // Libera as transações do bloco
        if (temp->transactions != NULL)
        {
            free(temp->transactions);
        }

        // Libera o bloco
        free(temp);
    }
}

void ataque(Block *blockchain)
{
    // Vamos fazer um ataque no segundo bloco da cadeia
    if (blockchain != NULL && blockchain->next != NULL)
    {
        Block *second_block = blockchain->next;

        // Modificando os dados do segundo bloco (pode ser qualquer modificação)
        strcpy(second_block->transactions[0].data, "Transação manipulada");

        // Recalcular a hashroot e hash após a alteração
        build_merkle_tree(second_block);
        char new_hash[65];
        calculate_hash(second_block, new_hash);
        strcpy(second_block->hash, new_hash);

        printf("\nAtaque realizado no bloco %d: Transação manipulada\n", second_block->index);
    }
}

void display_menu()
{
    printf("\n--- Blockchain Menu ---\n");
    printf("1. Criar bloco gênesis\n");
    printf("2. Adicionar um novo bloco\n");
    printf("3. Exibir blockchain completa\n");
    printf("4. Validar a blockchain\n");
    printf("5. Ataque\n");
    printf("6. Sair\n");
    printf("Escolha uma opção: ");
}

int main()
{
    int difficulty = 3;
    Block *blockchain = NULL;
    int option;
    Transaction transactions[10]; // Para armazenar até 10 transações por bloco
    int transaction_count = 0;

    do
    {
        display_menu();
        scanf("%d", &option);
        getchar();

        switch (option)
        {
        case 1:
            if (blockchain == NULL)
            {
                blockchain = create_genesis_block(difficulty);
                printf("Bloco gênesis criado com sucesso!\n");
            }
            else
            {
                printf("Bloco gênesis já existe!\n");
            }
            break;

        case 2:
            if (blockchain != NULL)
            {
                printf("Digite o número de transações: ");
                scanf("%d", &transaction_count);
                getchar();

                for (int i = 0; i < transaction_count; i++)
                {
                    printf("Digite os dados para a transação %d: ", i + 1);
                    fgets(transactions[i].data, sizeof(transactions[i].data), stdin);
                    transactions[i].data[strcspn(transactions[i].data, "\n")] = '\0';
                }

                add_block(&blockchain, transactions, transaction_count, difficulty);
                printf("Novo bloco adicionado com sucesso!\n");
            }
            else
            {
                printf("Crie o bloco gênesis primeiro!\n");
            }
            break;

        case 3:
            if (blockchain != NULL)
            {
                printf("Exibindo a blockchain completa:\n");
                print_blockchain(blockchain);
            }
            else
            {
                printf("Blockchain está vazia!\n");
            }
            break;

        case 4:
            if (blockchain != NULL)
            {
                validar(blockchain);
            }
            else
            {
                printf("Blockchain está vazia!\n");
            }
            break;

        case 5:
            if (blockchain != NULL)
            {
                ataque(blockchain); // Executando o ataque
                printf("Blockchain após o ataque:\n");
                print_blockchain(blockchain); // Mostrando a blockchain após o ataque
                validar(blockchain);          // Validando a blockchain após o ataque
            }
            else
            {
                printf("Crie a blockchain primeiro!\n");
            }
            break;

        case 6:
            printf("Saindo do programa...\n");
            break;

        default:
            printf("Opção inválida. Tente novamente.\n");
        }
    } while (option != 6);


    free_blockchain(blockchain);
    return 0;
}
