#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <cstdint>
#include <time.h>


//Simeck-64/128
__global__ void simeck(uint32_t *keys, uint32_t*ciphertext)
{
    int k = blockDim.x * blockIdx.x + threadIdx.x;
    uint32_t temp;
    uint32_t constant = 0xFFFFFFFC;
    uint64_t sequence = 0x938BCA3083F;
    uint32_t temp_result[2];
    uint32_t result[2];

    for (int i = 0; i < 44; i++) {
        //Round function
        asm("{\n\t"
            "mov.u32 %0, %1; \n\t"
            "shl.b32 %2, %1, 5; \n\t"
            "shr.b32 %3, %1, 27; \n\t"
            "or.b32 %4, %2, %3; \n\t"
            "shl.b32 %2, %1, 1; \n\t"
            "shr.b32 %3, %1, 31; \n\t"
            "or.b32 %5, %2, %3; \n\t"
            "and.b32 %1, %1, %4; \n\t"
            "xor.b32 %1, %1, %5; \n\t"
            "xor.b32 %1, %1, %6; \n\t"
            "xor.b32 %1, %1, %7; \n\t"
            "mov.u32 %6, %0; \n\t"
            "}"
            : "+r"(temp), "+r"(ciphertext[2 * k + 1]), "+r"(temp_result[0]) "+r"(temp_result[1]), "+r"(result[0]), "+r"(result[1]), "+r"(ciphertext[2 * k]), "+r"(keys[4 * k])
        );

        constant &= 0xFFFFFFFC;
        constant |= sequence & 1;
        sequence >>= 1;

        //Keyschedule
        asm("{\n\t"
            "mov.u32 %0, %1; \n\t"
            "shl.b32 %2, %1, 5; \n\t"
            "shr.b32 %3, %1, 27; \n\t"
            "or.b32 %4, %2, %3; \n\t"
            "shl.b32 %2, %1, 1; \n\t"
            "shr.b32 %3, %1, 31; \n\t"
            "or.b32 %5, %2, %3; \n\t"
            "and.b32 %1, %1, %4; \n\t"
            "xor.b32 %1, %1, %5; \n\t"
            "xor.b32 %1, %1, %6; \n\t"
            "xor.b32 %1, %1, %7; \n\t"
            "mov.u32 %6, %0; \n\t"
            "mov.u32 %0, %1; \n\t"
            "mov.u32 %1, %8; \n\t"
            "mov.u32 %8, %9; \n\t"
            "mov.u32 %9, %0; \n\t"
            "}"
            : "+r"(temp), "+r"(keys[4 * k + 1]), "+r"(temp_result[0]) "+r"(temp_result[1]), "+r"(result[0]), "+r"(result[1]), "+r"(keys[4 * k]), "+r"(constant), "+r"(keys[4 * k + 2]), "+r"(keys[4 * k + 3])
        );
    }
}



//Smion-64/128
__global__ void simon(uint32_t* K, uint32_t* Pt) {
    int k = blockDim.x * blockIdx.x + threadIdx.x;

    uint32_t c = 0xfffffffc;
    uint64_t z = 0xfc2ce51207a635db;
    uint32_t rk[44];
    rk[0] = K[4 * k]; rk[1] = K[4 * k + 1]; rk[2] = K[4 * k + 2]; rk[3] = K[4 * k + 3];

    uint32_t temp_result[2];
    uint32_t result[2];
    uint8_t i;

    //Keyschedule
    for (i = 4; i < 44; i++) {
        asm("{\n\t"
            "xor.b32 %2, %0, %1; \n\t" 
            "shr.b32 %4, %3, 3; \n\t"
            "shl.b32 %5, %3, 29; \n\t"
            "or.b32 %4, %4, %5; \n\t"
            "xor.b32 %2, %2, %4; \n\t"
            "xor.b32 %2, %2, %6; \n\t"
            "shr.b32 %4, %3, 4; \n\t"
            "shl.b32 %5, %3, 28; \n\t"
            "or.b32 %4, %4, %5; \n\t"
            "xor.b32 %2, %2, %4; \n\t"
            "shr.b32 %4, %6, 1; \n\t"
            "shl.b32 %5, %6, 31; \n\t"
            "or.b32 %4, %4, %5; \n\t"
            "xor.b32 %2, %2, %4; \n\t"
            "}"
            : "+r"(c), "+r"(rk[i - 4]), "+r"(rk[i]), "+r"(rk[i - 1]), "+r"(temp_result[0]), "+r"(temp_result[1]), "+r"(rk[i - 3])
        );
        rk[i] ^= (z & 1);
        z >>= 1;
    }

    ////Round function
    for (i = 0; i < 44; i = i + 2) {
        asm("{\n\t"
            "shl.b32 %1, %0, 1; \n\t"
            "shr.b32 %2, %0, 31; \n\t"
            "or.b32 %3, %1, %2; \n\t"
            "shl.b32 %1, %0, 8; \n\t"
            "shr.b32 %2, %0, 24; \n\t"
            "or.b32 %4, %1, %2; \n\t"
            "and.b32 %3, %3, %4; \n\t"
            "xor.b32 %5, %5, %3; \n\t"
            "shl.b32 %1, %0, 2; \n\t"
            "shr.b32 %2, %0, 30; \n\t"
            "or.b32 %1, %1, %2; \n\t"
            "xor.b32 %5, %5, %1; \n\t"
            "xor.b32 %5, %5, %6; \n\t"
            "shl.b32 %1, %5, 1; \n\t"
            "shr.b32 %2, %5, 31; \n\t"
            "or.b32 %3, %1, %2; \n\t"
            "shl.b32 %1, %5, 8; \n\t"
            "shr.b32 %2, %5, 24; \n\t"
            "or.b32 %4, %1, %2; \n\t"
            "and.b32 %3, %3, %4; \n\t"
            "xor.b32 %0, %0, %3; \n\t"
            "shl.b32 %1, %5, 2; \n\t"
            "shr.b32 %2, %5, 30; \n\t"
            "or.b32 %1, %1, %2; \n\t"
            "xor.b32 %0, %0, %1; \n\t"
            "xor.b32 %0, %0, %7; \n\t"
            "}"
            : "+r"(Pt[2 * k + 1]), "+r"(temp_result[0]), "+r"(temp_result[1]), "+r"(result[0]), "+r"(result[1]), "+r"(Pt[2 * k]), "+r"(rk[i]), "+r"(rk[i + 1])
            );
    }
}

//Speck-64128
__global__ void speck(uint32_t *K, uint32_t *Pt) {
    int k = blockDim.x * blockIdx.x + threadIdx.x;

    uint32_t temp_result[2];
    uint32_t result[2];
    uint32_t rk[27];
    uint32_t i;

    //Keyschedule
    uint32_t A = K[4 * k], B = K[4 * k + 1], C = K[4 * k + 2], D = K[4 * k + 3];
    for (i = 0; i<27;) {
        asm("{\n\t"\
            "mov.u32 %4, %0; \n\t"
            "shr.b32 %1, %3, 8; \n\t"
            "shl.b32 %2, %3, 24; \n\t"
            "or.b32 %3, %1, %2; \n\t"
            "add.u32 %3, %3, %0; \n\t"
            "xor.b32 %3, %3, %5; \n\t"
            "shl.b32 %1, %0, 3; \n\t"
            "shr.b32 %2, %0, 29; \n\t"
            "or.b32 %0, %1, %2; \n\t"
            "xor.b32 %0, %0, %3; \n\t" 
            "add.u32 %5, %5, 1; \n\t"
            "mov.u32 %8, %0; \n\t" 
            "shr.b32 %1, %6, 8; \n\t" 
            "shl.b32 %2, %6, 24; \n\t"
            "or.b32 %6, %1, %2; \n\t"
            "add.u32 %6, %6, %0; \n\t"
            "xor.b32 %6, %6, %5; \n\t"
            "shl.b32 %1, %0, 3; \n\t"
            "shr.b32 %2, %0, 29; \n\t"
            "or.b32 %0, %1, %2; \n\t"
            "xor.b32 %0, %0, %6; \n\t"
            "add.u32 %5, %5, 1; \n\t"
            "mov.u32 %9, %0; \n\t"
            "shr.b32 %1, %7, 8; \n\t"
            "shl.b32 %2, %7, 24; \n\t"
            "or.b32 %7, %1, %2; \n\t"
            "add.u32 %7, %7, %0; \n\t"
            "xor.b32 %7, %7, %5; \n\t"
            "shl.b32 %1, %0, 3; \n\t"
            "shr.b32 %2, %0, 29; \n\t"
            "or.b32 %0, %1, %2; \n\t"
            "xor.b32 %0, %0, %7; \n\t"
            "add.u32 %5, %5, 1; \n\t" 
            "}"
            : "+r"(A), "+r"(temp_result[0]), "+r"(temp_result[1]), "+r"(B), "+r"(rk[i]), "+r"(i), "+r"(C), "+r"(D), "+r"(rk[i+1]), "+r"(rk[i + 2])
           );
    }

    ////Round function
    for (i = 0; i < 27; i++) {
        asm("{\n\t"
            "shr.b32 %1, %0, 8; \n\t"
            "shl.b32 %2, %0, 24; \n\t"
            "or.b32 %0, %1, %2; \n\t"
            "add.u32 %0, %0, %3; \n\t"
            "xor.b32 %0, %0, %4; \n\t"
            "shl.b32 %1, %3, 3; \n\t"
            "shr.b32 %2, %3, 29; \n\t"
            "or.b32 %3, %1, %2; \n\t"
            "xor.b32 %3, %3, %0; \n\t"
            "}"
            : "+r"(Pt[2 * k + 1]), "+r"(temp_result[0]), "+r"(temp_result[1]), "+r"(Pt[2 * k]), "+r"(rk[i])
        );
    }
    
}


int main() {
    int blocknum = 35;
    int number = 1024 * blocknum;
    uint32_t text[1024 * 35][2];
    uint32_t key[1024 * 35][4];
    uint32_t* d_text, * d_key;
    time_t start, end;

    for (int i = 0; i < number; i++) {
        text[i][0] = 0xffffffff;
        text[i][1] = 0xffffffff;
        key[i][0] = 0xffffffff;
        key[i][1] = 0xffffffff;
        key[i][2] = 0xffffffff;
        key[i][3] = 0xffffffff;
    }
   
    cudaMalloc((void**)&d_text, sizeof(uint32_t) * number * 2);
    cudaMalloc((void**)&d_key, sizeof(uint32_t) * number * 4);

    start = clock();
    for (int i = 0; i < 100; i++) {
        cudaMemcpy(d_text, text, sizeof(uint32_t) * number * 2, cudaMemcpyHostToDevice);
        cudaMemcpy(d_key, key, sizeof(uint32_t) * number * 4, cudaMemcpyHostToDevice);

        simeck << < blocknum, number / blocknum >> > (d_key, d_text);
        //simon << < blocknum, number / blocknum >> > (d_key, d_text);
        //speck << < blocknum, number / blocknum >> > (d_key, d_text);

        cudaMemcpy(text, d_text, sizeof(uint32_t) * number * 2, cudaMemcpyDeviceToHost);
    }
    end = clock();

    printf("Elapsed time : %f\n", (double(end - start)/CLOCKS_PER_SEC)/100);
    return 0;
}
