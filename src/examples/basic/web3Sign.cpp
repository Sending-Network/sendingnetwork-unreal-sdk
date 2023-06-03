#include <cryptopp/sha.h>
#include <cryptopp/keccak.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>

using namespace CryptoPP;

class Web3Signer {
private:
    ECDSA<ECP, SHA256>::PrivateKey privateKey;

public:
    Web3Signer(const std::string& privateKeyHex) {
        HexDecoder decoder;
        decoder.Put((const byte*)privateKeyHex.data(), privateKeyHex.size());
        decoder.MessageEnd();

        privateKey.BERDecodePrivateKey(decoder, false, decoder.MaxRetrievable());
    }

    std::string signMessage(const std::string& message) {
        SHA256 hash;
        std::string digest;
        StringSource(message, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));

        AutoSeededRandomPool prng;
        ECDSA<ECP, SHA256>::Signer signer(privateKey);
        std::string signature;
        StringSource(digest, true, new SignerFilter(prng, signer, new HexEncoder(new StringSink(signature))));

        return signature;
    }
};