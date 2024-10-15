#pragma once
#include <windows.h>
#include <iostream>
#include <cstring>

DWORD getStringAsDWORD(const char* str) {
    DWORD value = 0;
    int len = std::strlen(str);

    for (int i = 0; i < len; ++i) {
        value = (value << 5) + value + str[i];  // Combine each character
    }

    return value;
}

DWORD WEIRDHASHA(_In_ const char* String, SIZE_T Iterations) {
    SIZE_T Index = 0;
    DWORD Hash = 5381;  // Starting with a prime number
    SIZE_T Length = Iterations;

    // Compute the hash with the given number of iterations
    while (Index != Length) {
        Hash = (Hash << 5) + Hash;  // Equivalent to Hash * 33
        Index++;
    }

    // Obtain DWORD from the first 4 characters of the string
    DWORD dwString = getStringAsDWORD(String);

    // Multiply the hash by this DWORD value
    return Hash * dwString + lstrlenA(String);
}
