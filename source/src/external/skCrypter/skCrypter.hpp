#pragma once
// Compile-time XOR string encryption.
// Strings are stored XOR-encrypted in the binary — plaintext never appears in .rdata.
// Usage:  const char* s = skCrypt("sensitive string");

#include <cstdint>
#include <cstddef>

namespace skc {

template<size_t N, uint8_t Key>
struct XorStrW {
    wchar_t buf_[N];

    __forceinline constexpr XorStrW(const wchar_t (&src)[N]) : buf_{} {
        for (size_t i = 0; i < N; ++i)
            buf_[i] = src[i] ^ static_cast<wchar_t>(Key ^ static_cast<uint8_t>(i * 13u + 7u));
    }

    __declspec(noinline) const wchar_t* get() const {
        static wchar_t tmp[N];
        for (size_t i = 0; i < N; ++i)
            tmp[i] = buf_[i] ^ static_cast<wchar_t>(Key ^ static_cast<uint8_t>(i * 13u + 7u));
        return tmp;
    }

    __forceinline operator const wchar_t*() const { return get(); }
};

template<size_t N, uint8_t Key>
struct XorStr {
    char buf_[N];

    __forceinline constexpr XorStr(const char (&src)[N]) : buf_{} {
        for (size_t i = 0; i < N; ++i)
            buf_[i] = src[i] ^ static_cast<char>(Key ^ static_cast<uint8_t>(i * 13u + 7u));
    }

    // noinline: prevents the optimizer from seeing through the XOR and storing plaintext
    __declspec(noinline) const char* get() const {
        static char tmp[N];
        for (size_t i = 0; i < N; ++i)
            tmp[i] = buf_[i] ^ static_cast<char>(Key ^ static_cast<uint8_t>(i * 13u + 7u));
        return tmp;
    }

    __forceinline operator const char*() const { return get(); }
};

} // namespace skc

// Each call site gets a unique Key via __COUNTER__, so two different strings
// with the same length never collide on the same template instantiation within a TU.
#define skCrypt(s) ([]() noexcept -> const char* {                                          \
    constexpr static ::skc::XorStr<sizeof(s), static_cast<uint8_t>(__COUNTER__)> _x_(s);   \
    return _x_.get();                                                                        \
}())

#define skCryptW(s) ([]() noexcept -> const wchar_t* {                                                          \
    constexpr static ::skc::XorStrW<sizeof(s)/sizeof(wchar_t), static_cast<uint8_t>(__COUNTER__)> _x_(s);      \
    return _x_.get();                                                                                            \
}())
