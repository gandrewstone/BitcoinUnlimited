// Copyright (c) 2020 G. Andrew Stone
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_STACK_ITEM_H
#define BITCOIN_STACK_ITEM_H

#include "script/bignum.h"
#include "utilstrencodings.h"

#include <assert.h>
#include <stdint.h>
#include <string>
#include <vector>

class CScript;

enum class StackElementType : uint8_t
{
    VCH = 0,
    BIGNUM = 1,
};

// An empty type that lets the StackItem constructor be specialized for vch construction
class VchStackType
{
};
extern VchStackType VchStack;

class BadOpOnType : std::exception
{
public:
    std::string reason;

    BadOpOnType(const std::string &r) : reason(r) {}
    BadOpOnType(const char *r) : reason(r) {}
    virtual const char *what() const noexcept { return reason.c_str(); }
};

typedef std::vector<unsigned char> VchType;

class StackItem
{
public:
    StackElementType type;

protected: // Because access should verify the type
    VchType vch;
    BigNum n;

public:
    // Default constructor sets its as a 0 size byte array
    StackItem() : type(StackElementType::VCH), vch(0) {}
    // construct a vch stack item from memory
    StackItem(const unsigned char *begin, const unsigned char *end) : type(StackElementType::VCH), vch(begin, end) {}
    /*
    StackItem(const std::vector<unsigned char>::iterator begin, const std::vector<unsigned char>::iterator end):
    type(StackElementType::VCH), vch(begin, end)
    {
    }

    StackItem(const std::vector<unsigned char>::reverse_iterator begin, const std::vector<unsigned
    char>::reverse_iterator end):
    type(StackElementType::VCH), vch(begin, end)
    {
    }
    StackItem(const std::vector<unsigned char>::const_reverse_iterator begin, const std::vector<unsigned
    char>::const_reverse_iterator end):
    type(StackElementType::VCH), vch(begin, end)
    {
    }
    */

    template <typename Iter>
    StackItem(Iter begin, Iter end) : type(StackElementType::VCH), vch(begin, end)
    {
    }


    StackItem(const VchType &buf) : type(StackElementType::VCH), vch(buf) {}
    // As std::vector, passing in a number allocates a vch of that length
    StackItem(unsigned int i) : type(StackElementType::VCH), vch(i) {}
    StackItem(VchStackType, unsigned int i) : type(StackElementType::VCH), vch(i) {}
    // As std::vector, passing in a number allocates a vch of that length
    StackItem(VchStackType, unsigned int count, const unsigned char value)
        : type(StackElementType::VCH), vch(count, value)
    {
    }

    StackItem(const BigNum &bn) : type(StackElementType::BIGNUM), n(bn) {}
    // Construct a StackItem as a vch if given a constant initializer of unsigned char
    // const StackItem example{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
    StackItem(const std::initializer_list<unsigned char> &ini)
        : type(StackElementType::VCH), vch(ini.begin(), ini.end())
    {
    }

    // Converts this stack item to a boolean as per the consensus rules around "true" stack script return values.
    operator bool() const;

    // operator CScript();

    const VchType &data() const
    {
        requireType(StackElementType::VCH);
        return vch;
    }

    VchType &mdata() // modifiable data
    {
        requireType(StackElementType::VCH);
        return vch;
    }

    const BigNum &num() const
    {
        requireType(StackElementType::BIGNUM);
        return n;
    }

    /** Converts this stack item into binary data.  Throws BadOpOnType if a conversion is impossible.
        BigNum implicit conversion uses a minimal-size (no zero padding) encoding.
    */
    VchType asVch() const
    {
        if (isVch())
            return vch;
        if (isBigNum())
        {
            return n.serialize(n.magSize() + 1);
        }
        throw BadOpOnType("cannot represent this item as a char vector");
    }

    /** Converts this stack item into a BigNum (or just returns it if its already a BigNum).  Throws BadOpOnType if
        a conversion is impossible.
    */
    BigNum asBigNum(const BigNum &bmd) const
    {
        if (isBigNum())
            return n;
        if (isVch())
        {
            BigNum des;
            des.deserialize(vch);
            return des.tdiv(bmd);
        }
        throw BadOpOnType("cannot represent this item as a BigNum");
    }

    /** Converts this stackitem into a uint64 if it is a ScriptNum compatible buffer or vch, or if it is a BigNum.
        @throws BadOpOnType if the number is out of range.
    */
    uint64_t asUint64(bool requireMinimal) const;

    /** Converts this stackitem into an int64 if it is a ScriptNum compatible buffer or vch, or if it is a BigNum.
        @throws BadOpOnType if the number is out of range.
    */
    int64_t asInt64(bool requireMinimal) const;

    // Returns 0xhexnum if this is a BigNum, or the straight hex if its a vch
    std::string hex()
    {
        if (type == StackElementType::BIGNUM)
            return n.str();
        if (type == StackElementType::VCH)
            return HexStr(vch);

        throw BadOpOnType("cannot represent this item as in hex");
    }

    BigNum &mnum()
    {
        requireType(StackElementType::BIGNUM);
        return n;
    }

    bool isVch(void) const { return type == StackElementType::VCH; }
    bool isBigNum(void) const { return type == StackElementType::BIGNUM; }
    void requireType(StackElementType t) const
    {
        if (type != t)
            throw BadOpOnType("Invalid operation on stack type");
    }

    // No BigNum is "empty"
    bool empty() const { return (isVch() && vch.empty()); }
    size_t size(void) const
    {
        requireType(StackElementType::VCH);
        return vch.size();
    }

    void clear(void)
    {
        type = StackElementType::VCH;
        vch.clear();
    }

    template <class ITER>
    void assign(ITER pbegin, ITER pend)
    {
        type = StackElementType::VCH;
        vch.assign(pbegin, pend);
    }

    void assign(const VchType &buf)
    {
        type = StackElementType::VCH;
        vch = buf;
    }

    void push_back(unsigned char c)
    {
        requireType(StackElementType::VCH);
        vch.push_back(c);
    }

    void reserve(size_t amt)
    {
        requireType(StackElementType::VCH);
        vch.reserve(amt);
    }

    void emplace_back(unsigned char arg)
    {
        requireType(StackElementType::VCH);
        vch.emplace_back(arg);
    }

    unsigned char &operator[](size_t idx)
    {
        requireType(StackElementType::VCH);
        assert(idx < vch.size());
        return vch[idx];
    }

    const unsigned char &operator[](size_t idx) const
    {
        requireType(StackElementType::VCH);
        assert(idx < vch.size());
        return vch[idx];
    }

    std::vector<unsigned char>::const_iterator begin() const
    {
        requireType(StackElementType::VCH);
        return vch.begin();
    }

    std::vector<unsigned char>::const_iterator end() const
    {
        requireType(StackElementType::VCH);
        return vch.end();
    }

    std::vector<unsigned char>::iterator begin()
    {
        requireType(StackElementType::VCH);
        return vch.begin();
    }

    std::vector<unsigned char>::iterator end()
    {
        requireType(StackElementType::VCH);
        return vch.end();
    }
};

#endif
