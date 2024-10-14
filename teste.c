/*
 * Data Encryption Standard
 * An approach to DES algorithm
 *
 * By: Daniel Huertas Gonzalez
 * Email: huertas.dani@gmail.com
 * Version: 0.1
 *
 * Based on the document FIPS PUB 46-3
 *
 * Codigo dele porem foi modificado por mim
 */
  
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LB32_MASK 0x00000001
#define LB64_MASK 0x0000000000000001
#define L64_MASK 0x00000000ffffffff
#define H64_MASK 0xffffffff00000000

/* Initial Permutation Table */
static char IP[] = {58, 50, 42, 34, 26, 18, 10, 2,  60, 52, 44, 36, 28,
                    20, 12, 4,  62, 54, 46, 38, 30, 22, 14, 6,  64, 56,
                    48, 40, 32, 24, 16, 8,  57, 49, 41, 33, 25, 17, 9,
                    1,  59, 51, 43, 35, 27, 19, 11, 3,  61, 53, 45, 37,
                    29, 21, 13, 5,  63, 55, 47, 39, 31, 23, 15, 7};

/* Inverse Initial Permutation Table */
static char PI[] = {40, 8,  48, 16, 56, 24, 64, 32, 39, 7,  47, 15, 55,
                    23, 63, 31, 38, 6,  46, 14, 54, 22, 62, 30, 37, 5,
                    45, 13, 53, 21, 61, 29, 36, 4,  44, 12, 52, 20, 60,
                    28, 35, 3,  43, 11, 51, 19, 59, 27, 34, 2,  42, 10,
                    50, 18, 58, 26, 33, 1,  41, 9,  49, 17, 57, 25};

/*Expansion table */
static char E[] = {32, 1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
                   8,  9,  10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
                   16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
                   24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};

/* Post S-Box permutation */
static char P[] = {16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23,
                   26, 5, 18, 31, 10, 2,  8,  24, 14, 32, 27,
                   3,  9, 19, 13, 30, 6,  22, 11, 4,  25};

/* The S-Box tables */
static char S[8][64] = {
    {/* S1 */
     14, 4,  13, 1, 2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0, 7,
     0,  15, 7,  4, 14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3, 8,
     4,  1,  14, 8, 13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5, 0,
     15, 12, 8,  2, 4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6, 13},
    {/* S2 */
     15, 1,  8,  14, 6,  11, 3,  4,  9,  7, 2,  13, 12, 0, 5,  10,
     3,  13, 4,  7,  15, 2,  8,  14, 12, 0, 1,  10, 6,  9, 11, 5,
     0,  14, 7,  11, 10, 4,  13, 1,  5,  8, 12, 6,  9,  3, 2,  15,
     13, 8,  10, 1,  3,  15, 4,  2,  11, 6, 7,  12, 0,  5, 14, 9},
    {/* S3 */
     10, 0,  9,  14, 6, 3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,
     13, 7,  0,  9,  3, 4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1,
     13, 6,  4,  9,  8, 15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,
     1,  10, 13, 0,  6, 9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12},
    {/* S4 */
     7,  13, 14, 3, 0,  6,  9,  10, 1,  2, 8, 5,  11, 12, 4,  15,
     13, 8,  11, 5, 6,  15, 0,  3,  4,  7, 2, 12, 1,  10, 14, 9,
     10, 6,  9,  0, 12, 11, 7,  13, 15, 1, 3, 14, 5,  2,  8,  4,
     3,  15, 0,  6, 10, 1,  13, 8,  9,  4, 5, 11, 12, 7,  2,  14},
    {/* S5 */
     2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0, 14, 9,
     14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9, 8,  6,
     4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3, 0,  14,
     11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4, 5,  3},
    {/* S6 */
     12, 1,  10, 15, 9, 2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
     10, 15, 4,  2,  7, 12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8,
     9,  14, 15, 5,  2, 8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
     4,  3,  2,  12, 9, 5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13},
    {/* S7 */
     4,  11, 2,  14, 15, 0, 8,  13, 3,  12, 9, 7,  5,  10, 6, 1,
     13, 0,  11, 7,  4,  9, 1,  10, 14, 3,  5, 12, 2,  15, 8, 6,
     1,  4,  11, 13, 12, 3, 7,  14, 10, 15, 6, 8,  0,  5,  9, 2,
     6,  11, 13, 8,  1,  4, 10, 7,  9,  5,  0, 15, 14, 2,  3, 12},
    {/* S8 */
     13, 2,  8,  4, 6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7,
     1,  15, 13, 8, 10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2,
     7,  11, 4,  1, 9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8,
     2,  1,  14, 7, 4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11}};

/* Permuted Choice 1 Table */
static char PC1[] = {57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18,
                     10, 2,  59, 51, 43, 35, 27, 19, 11, 3,  60, 52, 44, 36,

                     63, 55, 47, 39, 31, 23, 15, 7,  62, 54, 46, 38, 30, 22,
                     14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4};

/* Permuted Choice 2 Table */
static char PC2[] = {14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10,
                     23, 19, 12, 4,  26, 8,  16, 7,  27, 20, 13, 2,
                     41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
                     44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};

/* Iteration Shift Array */
static char iteration_shift[] = {
    /* 1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16 */
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

/*
 * The DES function
 * input: 64 bit message
 * key: 64 bit key for encryption/decryption
 * mode: 'e' = encryption; 'd' = decryption
 */
uint64_t des(uint64_t entrada, uint64_t chave, char modo) {

  int i, j;

  /* 8 bits */
  char linha, coluna;

  /* 28 bits */
  uint32_t C = 0;
  uint32_t D = 0;

  /* 32 bits */
  uint32_t L = 0;
  uint32_t R = 0;
  uint32_t s_saida = 0;
  uint32_t f_funcao_res = 0;
  uint32_t temporario = 0;

  /* 48 bits */
  uint64_t sub_chave[16] = {0};
  uint64_t s_entrada = 0;

  /* 56 bits */
  uint64_t permutacao_escolha_1 = 0;
  uint64_t permutacao_escolha_2 = 0;

  /* 64 bits */
  uint64_t permutacao_inicial_res = 0;
  uint64_t permutacao_inicial_inversa_res = 0;
  uint64_t saida_previa = 0;

  /* permutação inicial */
  for (i = 0; i < 64; i++) {

    permutacao_inicial_res <<= 1;
    permutacao_inicial_res |= (entrada >> (64 - IP[i])) & LB64_MASK;
  }

  L = (uint32_t)(permutacao_inicial_res >> 32) & L64_MASK;
  R = (uint32_t)permutacao_inicial_res & L64_MASK;

  /* cálculo inicial da chave */
  for (i = 0; i < 56; i++) {

    permutacao_escolha_1 <<= 1;
    permutacao_escolha_1 |= (chave >> (64 - PC1[i])) & LB64_MASK;
  }

  C = (uint32_t)((permutacao_escolha_1 >> 28) & 0x000000000fffffff);
  D = (uint32_t)(permutacao_escolha_1 & 0x000000000fffffff);

  /* Cálculo das 16 chaves */
  for (i = 0; i < 16; i++) {

    /* agenda da chave */
    // deslocamento de Ci e Di
    for (j = 0; j < iteration_shift[i]; j++) {

      C = 0x0fffffff & (C << 1) | 0x00000001 & (C >> 27);
      D = 0x0fffffff & (D << 1) | 0x00000001 & (D >> 27);
    }

    permutacao_escolha_2 = 0;
    permutacao_escolha_2 = (((uint64_t)C) << 28) | (uint64_t)D;

    sub_chave[i] = 0;

    for (j = 0; j < 48; j++) {

      sub_chave[i] <<= 1;
      sub_chave[i] |= (permutacao_escolha_2 >> (56 - PC2[j])) & LB64_MASK;
    }
  }

  for (i = 0; i < 16; i++) {

    /* função f(R,k) */
    s_entrada = 0;

    for (j = 0; j < 48; j++) {

      s_entrada <<= 1;
      s_entrada |= (uint64_t)((R >> (32 - E[j])) & LB32_MASK);
    }

    /*
     * Criptografia/Descriptografia
     * XOR entre R expandido e Ki
     */
    if (modo == 'd') {
      // descriptografia
      s_entrada = s_entrada ^ sub_chave[15 - i];

    } else {
      // criptografia
      s_entrada = s_entrada ^ sub_chave[i];
    }

    /* Tabelas S-Box */
    for (j = 0; j < 8; j++) {
      // 00 00 RCCC CR00 00 00 00 00 00 s_entrada
      // 00 00 1000 0100 00 00 00 00 00 mascara de linha
      // 00 00 0111 1000 00 00 00 00 00 mascara de coluna

      linha = (char)((s_entrada & (0x0000840000000000 >> 6 * j)) >> 42 - 6 * j);
      linha = (linha >> 4) | linha & 0x01;

      coluna =
          (char)((s_entrada & (0x0000780000000000 >> 6 * j)) >> 43 - 6 * j);

      s_saida <<= 4;
      s_saida |= (uint32_t)(S[j][16 * linha + coluna] & 0x0f);
    }

    f_funcao_res = 0;

    for (j = 0; j < 32; j++) {

      f_funcao_res <<= 1;
      f_funcao_res |= (s_saida >> (32 - P[j])) & LB32_MASK;
    }

    temporario = R;
    R = L ^ f_funcao_res;
    L = temporario;
  }

  saida_previa = (((uint64_t)R) << 32) | (uint64_t)L;

  /* inverse initial permutation */
  for (i = 0; i < 64; i++) {

    permutacao_inicial_inversa_res <<= 1;
    permutacao_inicial_inversa_res |=
        (saida_previa >> (64 - PI[i])) & LB64_MASK;
  }

  return permutacao_inicial_inversa_res;
}

#define BLOCO_BYTES 100
/*
 Union define uma região de memória compartilhada entre dois tipos de dados.
 Como uint64_t == 64 bits e char == 8 bits, logo, 8 char == 1 uint64_t
 Criptografamos usando uint64_t, mas o texto se encontra em char.
 Esse procedimento facilita a conversão de tipos mantendo a quantidade de bytes.
*/
union Texto_Cifrado {
  char texto[8 * BLOCO_BYTES];       // 1 bytes
  uint64_t bloco_bytes[BLOCO_BYTES]; // 8 bytes
};

int main(int argc, const char *argv[]) {

  int i, b;

  /// uint64_t entrada = 0x9474B8E8C73BCA7D;
  union Texto_Cifrado entrada;
  uint64_t chave = 0x0000000000000000;
  // uint64_t resultado = entrada;
  uint64_t resultado;
  // declara as variaveis de entrada e a chave para iniciar o algoritimo de criptografia


  /*
   * TESTING IMPLEMENTATION OF DES
   * Ronald L. Rivest
   * X0:  9474B8E8C73BCA7D
   * X16: 1B1A2DDB4C642438
   *
   * OUTPUT:
   * E: 8da744e0c94e5e17
   * D: 0cdb25e3ba3c6d79
   * E: 4784c4ba5006081f
   * D: 1cf1fc126f2ef842
   * E: e4be250042098d13
   * D: 7bfc5dc6adb5797c
   * E: 1ab3b4d82082fb28
   * D: c1576a14de707097
   * E: 739b68cd2e26782a
   * D: 2a59f0c464506edb
   * E: a5c39d4251f0a81e
   * D: 7239ac9a6107ddb1
   * E: 070cac8590241233
   * D: 78f87b6e3dfecf61
   * E: 95ec2578c2c433f0
   * D: 1b1a2ddb4c642438  <-- X16
   */

  printf("Digite um texto: ");
  scanf("%[^\n]s", entrada.texto);
  int tamanho_string = strlen(entrada.texto);
  //pega o texto escrito e ve seu tamanho
  // tamnho_string é o tamanho do texto digitado
  // ciel é para arredondar para cima o valor dividido por 8  

  int qtd_bytes_criptografados = ceil((float)tamanho_string / 8);

  for (b = 0; b < qtd_bytes_criptografados; b++) {
    resultado = entrada.bloco_bytes[b];
    for (i = 0; i < 16; i++) {

      if (i % 2 == 0) {

        resultado = des(resultado, resultado, 'e');
        // printf("E: %016llx\n", resultado);

      } else {

        resultado = des(resultado, resultado, 'd');
        // printf("D: %016llx\n", resultado);
      }
    }
    entrada.bloco_bytes[b] = resultado;
  }

  printf("Texto criptografado: ");
  for (b = 0; b < qtd_bytes_criptografados; b++) {
    printf("%016llx", entrada.bloco_bytes[b]);
  }
  /*for (b = 0; b < tamanho_string; b++) {
     printf("%c", entrada.texto[b]);
   }*/

  // result = des(input, key, 'e');
  // printf ("E: %016llx\n", result);

  // result = des(result, key, 'd');
  // printf ("D: %016llx\n", result);

  exit(0);
}
