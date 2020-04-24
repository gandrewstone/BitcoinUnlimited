// Copyright (c) 2020 G. Andrew Stone
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BIGNUM_H
#define BITCOIN_BIGNUM_H

#include <exception>
#include <gmp.h>
#include <stdarg.h>
#include <string>
#include <vector>

#define MAX_BIGNUM_MAGNITUDE_SIZE 512

extern mpz_t bigNumUpperLimit; // if (x > upperLimit) throw NUMBER_OUT_OF_RANGE;
extern mpz_t bigNumLowerLimit; // if (x < lowerLimit) throw NUMBER_OUT_OF_RANGE;

extern void BigNumInit();

class OutOfBounds : std::exception
{
public:
    std::string reason;

    OutOfBounds(const std::string &r) : reason(r) {}
    OutOfBounds(const char *r) : reason(r) {}
    virtual const char *what() const noexcept { return reason.c_str(); }
};


class BigNum
{
protected:
    mpz_t n;

public:
    BigNum(const std::string &str, int base = 10)
    {
        mpz_init(n);
        mpz_set_str(n, str.c_str(), base);
    }

    BigNum(const char *str, int base = 10)
    {
        mpz_init(n);
        mpz_set_str(n, str, base);
    }

    BigNum(long int i = 0) { mpz_init_set_si(n, i); }
    BigNum checkLimits() const
    {
        if (mpz_cmp(n, bigNumUpperLimit) > 0)
            throw OutOfBounds("Numerical upper bound exceeded");
        if (mpz_cmp(n, bigNumLowerLimit) < 0)
            throw OutOfBounds("Numerical lower bound exceeded");
        return *this;
    }

    /** Modulo where the remainder gets the sign of the dividend */
    BigNum tdiv(const BigNum &d) const
    {
        BigNum ret;
        mpz_tdiv_r(ret.n, n, d.n);
        return ret;
    }

    BigNum operator+(const BigNum &p) const
    {
        BigNum ret;
        mpz_add(ret.n, n, p.n);
        return ret.checkLimits();
    }

    BigNum operator-(const BigNum &p) const
    {
        BigNum ret;
        mpz_sub(ret.n, n, p.n);
        return ret.checkLimits();
    }

    BigNum operator-() const
    {
        BigNum ret;
        mpz_neg(ret.n, n);
        return ret.checkLimits();
    }

    BigNum operator*(const BigNum &p) const
    {
        BigNum ret;
        mpz_mul(ret.n, n, p.n);
        return ret.checkLimits();
    }

    BigNum operator/(const BigNum &p) const
    {
        BigNum ret;
        mpz_tdiv_q(ret.n, n, p.n);
        return ret.checkLimits();
    }

    BigNum operator%(const BigNum &p) const
    {
        BigNum ret;
        mpz_mod(ret.n, n, p.n);
        return ret.checkLimits();
    }

    std::string str(int base = 10) const
    {
        std::string ret;
        ret.resize(mpz_sizeinbase(n, base));
        mpz_get_str(&ret[0], base, n);
        return ret;
    }

    /** Fill buf with this BigNum in little-endian sign-magnitude format
        Returns the length of the buffer, which will be padTo+1,
        or on error it returns -1*length of the needed buffer (includes sign)
    */
    int serialize(unsigned char *buf, size_t padTo, int sz = 0) const
    {
        if (sz == 0)
            sz = padTo + 1; // If size is not provided, assume buf is exactly big enough for the chosen pad.
        int sizeNeeded = ((mpz_sizeinbase(n, 2) + 7) / 8) + 1;
        if (sizeNeeded > sz)
            return -sizeNeeded;
        size_t count = 0;
        mpz_export(buf, &count, -1, 1, 0, 0, n);
        while (count < padTo) // 0 pad the rest
        {
            buf[count] = 0;
            count++;
        }

        buf[count] = (mpz_sgn(n) == -1) ? 0x80 : 0;
        return count + 1;
    }

    /** Returns the required storage in bytes of the magnitude of this BigNum.  The minimum lossless serialization
is therefore 1 byte longer (for the sign). */
    size_t magSize() const { return ((mpz_sizeinbase(n, 2) + 7) / 8); }
    /** Return a byte vector of this BigNum in little-endian sign-magnitude format.
    */
    std::vector<unsigned char> serialize(size_t padTo) const
    {
        std::vector<unsigned char> ret;
        size_t mSize = magSize();
        ret.reserve(std::max(padTo + 1, mSize + 1));
        ret.resize(mSize);
        size_t count = 0;
        mpz_export(ret.data(), &count, -1, 1, 0, 0, n);
        while (count < padTo) // 0 pad the rest
        {
            ret.push_back(0);
            count++;
        }

        ret.push_back((mpz_sgn(n) == -1) ? 0x80 : 0);
        return ret;
    }

    /** Read this BigNum from a little-endian sign-magnitude formatted buffer */
    BigNum &deserialize(unsigned char *buf, int bufsize)
    {
        // CScriptNum uses a slightly different format which allows the sign bit to be packed into the mag bytes
        if (buf[bufsize - 1] >= 0x80)
        {
            auto tmp = buf[bufsize - 1];
            buf[bufsize - 1] &= 0x7f;
            mpz_import(n, bufsize, -1, 1, 0, 0, buf);
            mpz_neg(n, n);
            buf[bufsize - 1] = tmp;
        }
        else
            mpz_import(n, bufsize, -1, 1, 0, 0, buf);
        return *this;
    }

    BigNum &deserialize(const std::vector<unsigned char> &c)
    {
        std::vector<unsigned char> cpy = c;
        return deserialize(cpy.data(), cpy.size());
    }

    /** Return this bignum's magnitude (the sign is ignored) as an unsigned 64 bit integer.
        If this BigNum is too large, the least significant 64 bits are returned.
    */
    unsigned long int asUint64() const { return mpz_get_ui(n); }
    // Logic:
    bool operator==(const BigNum &p) const { return (mpz_cmp(n, p.n) == 0); }
    bool operator!=(const BigNum &p) const { return (mpz_cmp(n, p.n) != 0); }
    bool operator<(const BigNum &p) const { return (mpz_cmp(n, p.n) < 0); }
    bool operator>(const BigNum &p) const { return (mpz_cmp(n, p.n) > 0); }
    bool operator<=(const BigNum &p) const { return (mpz_cmp(n, p.n) <= 0); }
    bool operator>=(const BigNum &p) const { return (mpz_cmp(n, p.n) >= 0); }
    bool operator==(const unsigned long int p) const { return (mpz_cmp_ui(n, p) == 0); }
    bool operator==(const long int p) const { return (mpz_cmp_si(n, p) == 0); }
};

inline BigNum operator"" _BN(const char *str)
{
    if (str[1] == 'x')
        return BigNum(str + 2, 16);
    return BigNum(str, 10);
}


#endif
