#define THREADS 1024
#define BLOCKS 12
#define WORK_BY_TIME 1

#define SIZE_VECTOR (THREADS * WORK_BY_TIME) * BLOCKS


// Variável de loop para o intervalo de senha
unsigned long first_pwd = 3002900000;
unsigned long last_pwd = 4000000000;
unsigned long cpassword = 3003000669;
