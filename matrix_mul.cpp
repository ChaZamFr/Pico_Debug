#include <stdio.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"

#include "pico/time.h"

/* small workload  */
#define NRA 11                 /* number of rows in matrix A */
#define NCA 12                 /* number of columns in matrix A */
#define NCB 9                 /* number of columns in matrix B */

int a[NRA][NCA],           /* matrix A to be multiplied */
    b[NCA][NCB],           /* matrix B to be multiplied */
    c[NRA][NCB];           /* result matrix C */

int FAULT = 0;
int sum = 0;

extern "C" {
  void START_F_INJECT()
  {
  }

  void END_F_INJECT()
  {
  }

  void FAULT_CHECK()
  {
  }
}
int main(int argc, char *argv[]) 
{
  stdio_init_all();
  int i,j,k;
  int ret=0;

  for (i=0; i<NRA; i++)
    for (j=0; j<NCA; j++)
      a[i][j]= i+j;

  for (i=0; i<NCA; i++)
    for (j=0; j<NCB; j++)
      b[i][j]= i*j;

  for (i=0; i<NRA; i++)
    for (j=0; j<NCB; j++)
      c[i][j]= 0;

  while(1)
  {
    /*indicate start of fault injection*/
    START_F_INJECT();

    /* start computation */
    for (i=0; i<NRA; i++)    
    {
      for(j=0; j<NCB; j++) 
      { 
        c[i][j]=0;
        for (k=0; k<NCA; k++)
          c[i][j] += a[i][k] * b[k][j];
      }
    }
    /* end computation */
    
    /*indicate end of fault injection*/
    END_F_INJECT();

    /*check for fault*/
    sum = 0;
    for (i=0; i<NRA; i++)    
    {
      for(j=0; j<NCB; j++)       
        for (k=0; k<NCA; k++)
          sum += c[i][j];
    }
    printf("Sum = %d\n", sum);
    if (sum != 3972672)
      FAULT = 1;   	/* fault detected */
    else 
      FAULT = 0;    /* no fault */

    /* indicate gdb to check for fault */ 
    FAULT_CHECK();
  }  
  return 0;
}


