#include "script/bignum.h"

mpz_t upperLimit;  // if (x > upperLimit) throw NUMBER_OUT_OF_RANGE;
mpz_t lowerLimit;  // if (x < lowerLimit) throw NUMBER_OUT_OF_RANGE;

void BigNumInit()
{
    mpz_init_set_ui (upperLimit, 1);
    mpz_mul_2exp(upperLimit, upperLimit, 4096);
    mpz_neg (lowerLimit, upperLimit);
    mpz_sub_ui (upperLimit, upperLimit, 1);
    mpz_add_ui (lowerLimit, lowerLimit, 1);
}

