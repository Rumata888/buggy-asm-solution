#include <ecc/curves/bn254/g1.hpp>
#include <crypto/hashers/hashers.hpp>
#include <crypto/aes128/aes128.hpp>
#include <crypto/sha256/sha256.hpp>
#include <sstream>
using namespace barretenberg;
struct ServerState {
    g1::affine_element publicKey;
    fr privateKey;
    uint8_t sessionEncryptionKey[32];
    uint8_t sessionMACKey[32];
};

extern "C" ServerState* initializeState(uint256_t* pPrivateKey)
{
    ServerState* serverState = new ServerState();
    serverState->privateKey = fr(*pPrivateKey);
    serverState->publicKey = g1::affine_element(g1::one * serverState->privateKey);
    return serverState;
}

extern "C" void deleteState(ServerState* pServerState)
{
    delete pServerState;
}

extern "C" void getPublicKey(ServerState* pServerState, uint8_t* pOutputBuffer)
{
    *((uint256_t*)pOutputBuffer) = pServerState->publicKey.x;

    *((uint256_t*)(pOutputBuffer + sizeof(uint256_t))) = pServerState->publicKey.y;
}
extern "C" bool computeFaulty(uint8_t* pPointCoordinates)
{
    fq clientPointX(*(uint256_t*)(pPointCoordinates)),
        clientPointY(*(uint256_t*)(pPointCoordinates + sizeof(uint256_t)));
    g1::affine_element clientPoint(clientPointX, clientPointY);
    if (!clientPoint.on_curve()) {
        std::cout << "Not on curve!" << std::endl;
        std::cout << clientPointX << std::endl;
        std::cout << clientPointY << std::endl;
        return false;
    }

    g1::affine_element doubled = g1::affine_element((clientPoint * fr(2)));
    *(uint256_t*)(pPointCoordinates) = doubled.x;
    *(uint256_t*)(pPointCoordinates + sizeof(uint256_t)) = doubled.y;
    return true;
}
extern "C" bool createSession(ServerState* pServerState, uint8_t* pPointCoordinates, char* pErrorMessage)
{
    std::stringstream errorStream;
    fq clientPointX(*(uint256_t*)(pPointCoordinates)),
        clientPointY(*(uint256_t*)(pPointCoordinates + sizeof(uint256_t)));
    g1::affine_element clientPoint(clientPointX, clientPointY);
    if (!clientPoint.on_curve()) {
        errorStream << "Input point " << clientPoint << " is not on curve" << std::endl;
        strcpy(pErrorMessage, errorStream.str().c_str());
        return false;
    }

    g1::affine_element sharedPoint =
        g1::affine_element((clientPoint * fr(2)) * (pServerState->privateKey * fr(2).invert()));
    if (!sharedPoint.on_curve()) {
        errorStream << "Shared point " << sharedPoint << " is not on curve" << std::endl;
        strcpy(pErrorMessage, errorStream.str().c_str());

        return false;
    }
    uint256_t sharedPointX(sharedPoint.x), sharedPointY(sharedPoint.y);
    std::vector<uint8_t> hasherInput;
    std::vector<uint8_t> temp;
    for (size_t i = 0; i < sizeof(uint256_t); i++) {
        hasherInput.push_back(((uint8_t*)(&sharedPointX.data[0]))[i]);
    }
    for (size_t i = 0; i < sizeof(uint256_t); i++) {
        hasherInput.push_back(((uint8_t*)(&sharedPointY.data[0]))[i]);
    }
    temp.insert(temp.begin(), hasherInput.begin(), hasherInput.end());
    temp.push_back(0);
    auto encryptionKey = Sha256Hasher::hash(temp);
    temp.pop_back();
    temp.push_back(1);
    auto macKey = Sha256Hasher::hash(temp);

    memcpy(pServerState->sessionEncryptionKey, encryptionKey.data(), 32);
    memcpy(pServerState->sessionMACKey, macKey.data(), 32);
    return true;
}

extern "C" bool decryptWithSessionKey(ServerState* pServerState,
                                      uint8_t* pIV,
                                      uint8_t* pInputBuffer,
                                      uint8_t* pOutputBuffer,
                                      size_t bufferSize,
                                      uint8_t* pMAC)
{
    std::vector<uint8_t> encrypted;
    encrypted.reserve(bufferSize);
    for (size_t i = 0; i < bufferSize; i++) {
        encrypted.push_back(*(pInputBuffer + i));
    }
    auto encrypted_hash_bytes = Sha256Hasher::hash(encrypted);
    for (size_t i = 0; i < 32; i++) {
        encrypted_hash_bytes.push_back(pServerState->sessionMACKey[i]);
    }
    auto mac = Sha256Hasher::hash(encrypted_hash_bytes);
    if (memcmp(pMAC, mac.data(), 32)) {
        return false;
    }
    if (bufferSize < 16) {
        return false;
    }
    memcpy(pOutputBuffer, pInputBuffer, bufferSize);
    crypto::aes128::decrypt_buffer_cbc(pOutputBuffer, pIV, pServerState->sessionEncryptionKey, bufferSize);
    return true;
}

extern "C" bool encryptWithSessionKey(ServerState* pServerState,
                                      uint8_t* pIV,
                                      uint8_t* pInputBuffer,
                                      uint8_t* pOutputBuffer,
                                      size_t bufferSize,
                                      uint8_t* pMAC)
{
    uint8_t ivCopy[16];
    if (bufferSize < 16) {
        return false;
    }
    memcpy(ivCopy, pIV, 16);
    memcpy(pOutputBuffer, pInputBuffer, bufferSize);
    crypto::aes128::encrypt_buffer_cbc(pOutputBuffer, ivCopy, pServerState->sessionEncryptionKey, bufferSize);
    std::vector<uint8_t> encrypted;
    encrypted.reserve(bufferSize);
    for (size_t i = 0; i < bufferSize; i++) {
        encrypted.push_back(*(pOutputBuffer + i));
    }
    auto encrypted_hash_bytes = Sha256Hasher::hash(encrypted);
    for (size_t i = 0; i < 32; i++) {
        encrypted_hash_bytes.push_back(pServerState->sessionMACKey[i]);
    }
    auto mac = Sha256Hasher::hash(encrypted_hash_bytes);
    memcpy(pMAC, mac.data(), 32);
    return true;
}
