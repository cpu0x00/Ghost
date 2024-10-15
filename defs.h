#pragma once

#define SELF_HANDLE (HANDLE)(-1)
#define CURRENT_THREAD (HANDLE)(-2)
#define HANDLE_ERROR(FUNCTION, ERROR_MSG) std::cout  << FUNCTION << ": " << #ERROR_MSG << std::endl;
#define NTAPI_ERR(NTAPI, status) std::cout << "{!!} " << #NTAPI << " failed with status: " << std::hex << status << std::endl;
#define PRINT(DATA) std::cout << #DATA << std::endl;
#define API_ERR(API) std::cout << #API << " Failed with Error Code: " << GetLastError() << std::endl; 
#define NTAPI_VALIDATE_RETURN(API_NAME, STATUS) if (STATUS != 0){std::cout << "{!!} " << #API_NAME << " failed with status: " << std::hex << STATUS << std::endl; return -1;};
#define NTAPI_VALIDATE_RETURN2VOID(API_NAME, STATUS) if (STATUS != 0){std::cout << "{!!} " << #API_NAME << " failed with status: " << std::hex << STATUS << std::endl; return;};
#define NTAPI_VALIDATE_RETURN2NULL(API_NAME, STATUS) if (STATUS != 0){std::cout << "{!!} " << #API_NAME << " failed with status: " << std::hex << STATUS << std::endl; return NULL;};
#define InitializeRC4EncryptionDecryptionData(DataUstring, buffer, length) {RtlSecureZeroMemory(DataUstring, sizeof(USTRING)); (DataUstring)->Buffer = buffer; (DataUstring)->Length = length; (DataUstring)->MaximumLength = length;};// Properly initializes the RC4 Data structure
#define InitializeRC4EncryptionDecryptionKey(KeyUstring, buffer, length) { RtlSecureZeroMemory(KeyUstring, sizeof(USTRING)); (KeyUstring)->Buffer = buffer; (KeyUstring)->Length = length; (KeyUstring)->MaximumLength = length;}; // Properly initializes the RC4 Key structure 
#define _DEBUG_PRINT // undef this to remove the print statements during compilation