#include "openssl/evp.h"
#include "cipher.h"

extern "C"
{
	ICipher * createCipher(const std::string& cipherName)
	{
		return new cipher::Cipher(cipherName);
	}
	void releaseCipher(ICipher *p)
	{
		delete p;
	}
}

namespace cipher {
	Cipher::Cipher(const std::string & cipherName)
		:m_cipher(nullptr)
		,m_cipherName(cipherName)
	{
		m_cipher = EVP_get_cipherbyname(cipherName.c_str());
		if (m_cipher == nullptr) {
			throw std::runtime_error("get cipher failed!");
		}
		m_ctx = EVP_CIPHER_CTX_new();
		if (m_ctx == nullptr)
		{
			throw std::runtime_error("get ctx failed!");
		}
	}

	Cipher::~Cipher()
	{
		if (m_ctx)
		{
			EVP_CIPHER_CTX_free(m_ctx);
		}
	}

	bool Cipher::Init(const std::string & keyStr, int isEncrypt)
	{
		unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
		int key_len = EVP_BytesToKey(m_cipher, EVP_md5(), NULL, (unsigned char*)keyStr.data(), static_cast<int>(keyStr.length()), 1, key, iv);

		EVP_CIPHER_CTX_init(m_ctx);
		EVP_CipherInit(m_ctx, m_cipher, (unsigned char *)key, (unsigned char *)iv, isEncrypt);
		if (!EVP_CIPHER_CTX_set_key_length(m_ctx, key_len)) {
			fprintf(stderr, "node-crypto : Invalid key length %d\n", key_len);
			EVP_CIPHER_CTX_cleanup(m_ctx);
			return false;
		}
		return true;
	}

	int Cipher::Update(const std::string & inData, std::string & outData)
	{
		int len = static_cast<int>(inData.length());
		int oLen = len + EVP_CIPHER_CTX_block_size(m_ctx);
		unsigned char* out = new unsigned char[oLen];
		int ret = EVP_CipherUpdate(m_ctx, out, &oLen, (unsigned char*)inData.c_str(), len);
		outData.append((char*)out, oLen);
		delete out;
		return ret;
	}

	int Cipher::Update(const char * inData, const int & inLen, std::string & outData)
	{
		int oLen = inLen + EVP_CIPHER_CTX_block_size(m_ctx);
		unsigned char* out = new unsigned char[oLen];
		int ret = EVP_CipherUpdate(m_ctx, out, &oLen, (unsigned char*)inData, inLen);
		outData.append((char*)out, oLen);
		delete out;
		return ret;
	}

	int Cipher::Update(std::istream & iStream, std::ostream & oStream)
	{
		if (iStream.rdstate() != std::ios::goodbit || oStream.rdstate() != std::ios::goodbit)
		{
			std::cerr << __FUNCTION__<< " file rdstate not good!" << std::endl;
			return 0;
		}

		const int len = 4096;
		char in[len] = { 0 };

		int oLen = len + EVP_CIPHER_CTX_block_size(m_ctx);
		unsigned char* out = new unsigned char[oLen];
		
		int size = 0;
		while (iStream.read(in, len))
		{
			size = static_cast<int>(iStream.gcount());
			int ret = EVP_CipherUpdate(m_ctx, out, &oLen, (unsigned char*)in, size);
			oStream.write((const char*)out, oLen);
		}
		if (iStream.eof())
		{
			size = static_cast<int>(iStream.gcount());
			int ret = EVP_CipherUpdate(m_ctx, out, &oLen, (unsigned char*)in, size);
			oStream.write((const char*)out, oLen);
		}
		return 0;
	}

	int Cipher::Final(std::string & outData, bool toleratePadding)
	{
		
		int oLen = EVP_CIPHER_CTX_block_size(m_ctx);
		unsigned char* out = new unsigned char[oLen];
		EVP_CipherFinal(m_ctx,out, &oLen);
		outData.append((char*)out, oLen);
		EVP_CIPHER_CTX_cleanup(m_ctx);
		return 0;
	}

	int Cipher::Final(std::ostream & oStream, bool toleratePadding)
	{
		if (oStream.rdstate() != std::ios::goodbit)
		{
			std::cerr << __FUNCTION__ << "file rdstate not good!" << std::endl;
			return 0;
		}
		int oLen = EVP_CIPHER_CTX_block_size(m_ctx);
		unsigned char* out = new unsigned char[oLen];
		EVP_CipherFinal(m_ctx, out, &oLen);
		oStream.write((const char*)out, oLen);
		EVP_CIPHER_CTX_cleanup(m_ctx);
		return 0;
	}

	int Cipher::GetNid() const
	{
		return EVP_CIPHER_nid(m_cipher);
	}

	int Cipher::GetBlockSize() const
	{
		return EVP_CIPHER_block_size(m_cipher);
	}

	int Cipher::GetKeyLength() const
	{
		return EVP_CIPHER_key_length(m_cipher);
	}

	int Cipher::GetIVLength() const
	{
		return EVP_CIPHER_iv_length(m_cipher);
	}

	int Cipher::GetMode() const
	{
		return 0;
	}
};

