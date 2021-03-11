#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"

#include "pkey.h"
#include <algorithm>
#include <iostream>

extern "C"
{
	IPKey * createPKey(const std::string & pkeyName)
	{
		return pkey::PKey::createPkey(pkeyName);
	};

	void releasePKey(IPKey *p)
	{
		delete p;
	};
}

namespace pkey {

	std::unordered_map< std::string, const int> PKey::pkeyname2nid = {
	{"rsa",EVP_PKEY_RSA}
	};

	IPKey * PKey::createPkey(const std::string & keyName)
	{
		std::string pkeyName = pkeyName;
		std::transform(pkeyName.begin(), pkeyName.end(), pkeyName.begin(), ::toupper);
		auto& iter = pkeyname2nid.find(pkeyName);
		if (iter != pkeyname2nid.end())
		{
			return new PKey(iter->second);
		}

		return nullptr;
	}

	PKey::PKey(int pkeyNid)
		: m_ctx(nullptr)
		, m_pkey(nullptr)
		, m_cipherCtx(nullptr)
		, m_pkeyNid(EVP_PKEY_RSA)
	{
	}
	PKey::~PKey()
	{
		if (m_ctx != nullptr)
		{
			EVP_PKEY_CTX_free(m_ctx);
		}
		if (m_pkey != nullptr)
		{
			EVP_PKEY_free(m_pkey);
		}
		if (m_cipherCtx != nullptr)
		{
			EVP_CIPHER_CTX_free(m_cipherCtx);
		}
	}
	bool PKey::Genkey(int rsabits)
	{
		do
		{
			if (EVP_PKEY_keygen_init(m_ctx) <= 0)
			{
				break;
			}
			if (EVP_PKEY_CTX_set_rsa_keygen_bits(m_ctx, rsabits) <= 0)
			{
				break;
			}
			if (EVP_PKEY_keygen(m_ctx, &m_pkey) <= 0)
			{
				break;
			}
			return true;
		} while (false);

		EVP_PKEY_CTX_free(m_ctx);
		return false;
	}

	bool PKey::LoadPublicKey(const std::string & fullpath)
	{
		BIO * file = nullptr;
		file = BIO_new_file(fullpath.c_str(), "r");
		auto ret = PEM_read_bio_PUBKEY(file, &m_pkey, nullptr, nullptr);
		BIO_free(file);
		return ret != nullptr ? true : false;

	}
	bool PKey::LoadPrivateKey(const std::string & fullpath)
	{
		BIO * file = nullptr;
		file = BIO_new_file(fullpath.c_str(), "r");
		auto ret = PEM_read_bio_PrivateKey(file, &m_pkey, nullptr, nullptr);
		BIO_free(file);
		return ret != nullptr ? true : false;
	}
	bool PKey::SavePublicKey(const std::string & fullpath)
	{
		BIO * file = nullptr;
		file = BIO_new_file(fullpath.c_str(), "w");
		int ret = PEM_write_bio_PUBKEY(file, m_pkey);
		BIO_free(file);
		return ret == 0 ? true : false;
	}
	bool PKey::SavePrivateKey(const std::string & fullpath)
	{
		BIO * file = nullptr;
		file = BIO_new_file(fullpath.c_str(), "w");
		int ret = PEM_write_bio_PrivateKey(file, m_pkey,nullptr,nullptr,0,nullptr,nullptr);
		BIO_free(file);
		return ret == 0 ? true : false;
	}

	bool PKey::Sign(const std::string & data, std::string& outData, const std::string & mdTpye)
	{
		int ret = 0;
		const EVP_MD * type = nullptr;
		EVP_MD_CTX * pMdCtx = nullptr;
		do
		{
			pMdCtx = EVP_MD_CTX_create();
			if (pMdCtx == nullptr)
			{
				break;
			}
			EVP_MD_CTX_init(pMdCtx);
			type = EVP_get_digestbyname(mdTpye.c_str());
			if (type == nullptr)
			{
				break;
			}
			ret = EVP_SignInit_ex(pMdCtx, type, nullptr);
			if (ret != 1)
			{
				break;
			}
			ret =  EVP_SignUpdate(pMdCtx, data.c_str(), data.size());
			if (ret != 1)
			{
				break;
			}

			std::vector<unsigned char> md(EVP_PKEY_size(m_pkey), 0);
			unsigned int s;
			ret = EVP_SignFinal(pMdCtx, md.data(), &s, m_pkey);
			if (ret != 1)
			{
				break;
			}

			outData.append((const char*)md.data(), s);

			if (pMdCtx != nullptr)
			{
				EVP_MD_CTX_free(pMdCtx);
			}
			return true;
		} while (false);
	
		if (pMdCtx != nullptr)
		{
			EVP_MD_CTX_free(pMdCtx);
		}

		return false;
	}

	bool PKey::Verify(const std::string & data, const std::string & sigData, const std::string & mdTpye)
	{
		//	//int EVP_VerifyInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
//	//int EVP_VerifyUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt);
//	//int EVP_VerifyFinal(EVP_MD_CTX *ctx, unsigned char *sigbuf, unsigned int siglen,
//	//	EVP_PKEY *pkey);
		int ret = 0;
		const EVP_MD * type = nullptr;
		EVP_MD_CTX * pMdCtx = nullptr;
		do
		{
			pMdCtx = EVP_MD_CTX_create();
			if (pMdCtx == nullptr)
			{
				break;
			}
			EVP_MD_CTX_init(pMdCtx);
			type = EVP_get_digestbyname(mdTpye.c_str());
			if (type == nullptr)
			{
				break;
			}
			ret = EVP_VerifyInit_ex(pMdCtx, type, nullptr);
			if (ret != 1)
			{
				break;
			}
			ret = EVP_VerifyUpdate(pMdCtx, data.c_str(), data.size());
			if (ret != 1)
			{
				break;
			}

			int ret = EVP_VerifyFinal(pMdCtx,(const unsigned char*)sigData.c_str(), static_cast<unsigned int>(sigData.size()),m_pkey);
			if (pMdCtx != nullptr)
			{
				EVP_MD_CTX_free(pMdCtx);
			}
			return ret == 1?true:false;
		} while (false);

		if (pMdCtx != nullptr)
		{
			EVP_MD_CTX_free(pMdCtx);
		}
		return false;
	}

	bool PKey::Sign(std::istream & iStream, std::string& outData, const std::string & mdTpye)
	{
		if (iStream.rdstate() != std::ios::goodbit )
		{
			std::cerr << __FUNCTION__ << " file rdstate not good!" << std::endl;
			return 0;
		}

		int ret = 0;
		const EVP_MD * type = nullptr;
		EVP_MD_CTX * pMdCtx = nullptr;
		do
		{
			pMdCtx = EVP_MD_CTX_create();
			if (pMdCtx == nullptr)
			{
				break;
			}
			EVP_MD_CTX_init(pMdCtx);
			type = EVP_get_digestbyname(mdTpye.c_str());
			if (type == nullptr)
			{
				break;
			}
			ret = EVP_SignInit_ex(pMdCtx, type, nullptr);
			if (ret != 1)
			{
				break;
			}

			const int len = 4096;
			char in[len] = { 0 };

			int size = 0;
			while (iStream.read(in, len))
			{
				size = static_cast<int>(iStream.gcount());
				ret = EVP_SignUpdate(pMdCtx, (unsigned char*)in, size);
			}

			if (ret != 1)
			{
				break;
			}
			if (iStream.eof())
			{
				size = static_cast<int>(iStream.gcount());
				ret = EVP_SignUpdate(pMdCtx, (unsigned char*)in, size);
			}
			if (ret != 1)
			{
				break;
			}
			std::vector<unsigned char> md(EVP_PKEY_size(m_pkey), 0);
			unsigned int s;
			ret = EVP_SignFinal(pMdCtx, md.data(), &s, m_pkey);
			if (ret != 1)
			{
				break;
			}

			outData.append((const char*)md.data(), s);

			if (pMdCtx != nullptr)
			{
				EVP_MD_CTX_free(pMdCtx);
			}
			return true;
		} while (false);

		if (pMdCtx != nullptr)
		{
			EVP_MD_CTX_free(pMdCtx);
		}
		return false;
	}

	bool PKey::Verify(std::istream & iStream, const std::string& sigData, const std::string & mdTpye)
	{
		int ret = 0;
		const EVP_MD * type = nullptr;
		EVP_MD_CTX * pMdCtx = nullptr;
		do
		{
			pMdCtx = EVP_MD_CTX_create();
			if (pMdCtx == nullptr)
			{
				break;
			}
			EVP_MD_CTX_init(pMdCtx);
			type = EVP_get_digestbyname(mdTpye.c_str());
			if (type == nullptr)
			{
				break;
			}
			ret = EVP_VerifyInit_ex(pMdCtx, type, nullptr);
			if (ret != 1)
			{
				break;
			}
			const int len = 4096;
			char in[len] = { 0 };

			int size = 0;
			while (iStream.read(in, len))
			{
				size = static_cast<int>(iStream.gcount());
				ret = EVP_VerifyUpdate(pMdCtx, (unsigned char*)in, size);
			}

			if (ret != 1)
			{
				break;
			}
			if (iStream.eof())
			{
				size = static_cast<int>(iStream.gcount());
				ret = EVP_VerifyUpdate(pMdCtx, (unsigned char*)in, size);
			}
			if (ret != 1)
			{
				break;
			}

			int ret = EVP_VerifyFinal(pMdCtx, (const unsigned char*)sigData.c_str(), static_cast<unsigned int>(sigData.size()), m_pkey);
			if (pMdCtx != nullptr)
			{
				EVP_MD_CTX_free(pMdCtx);
			}
			return ret == 1 ? true : false;
		} while (false);

		if (pMdCtx != nullptr)
		{
			EVP_MD_CTX_free(pMdCtx);
		}
		return false;
	}

	bool PKey::Encrypt(const std::string & inData, std::string & outData)
	{
		size_t outlen = 0;
		do
		{
			if (EVP_PKEY_encrypt_init(m_ctx) <= 0)
			{
				break;
			}
			if (EVP_PKEY_CTX_set_rsa_padding(m_ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
			{
				break;
			}
			if (EVP_PKEY_encrypt(m_ctx, NULL, &outlen, (const unsigned char*)inData.data(), inData.length()) <= 0)
			{
				break;
			}
			std::vector<unsigned char> out(outlen,0);
			if (EVP_PKEY_encrypt(m_ctx, out.data(), &outlen, (const unsigned char*)inData.data(), inData.length()) <= 0)
			{
				break;
			}
			outData.append((const char*)out.data(), outlen);
			return true;
		} while (false);
		return false;
	}

	bool PKey::Decrypt(const std::string & inData, std::string & outData)
	{
		size_t outlen = 0;
		do
		{
			if (EVP_PKEY_decrypt_init(m_ctx) <= 0)
			{
				break;
			}
			if (EVP_PKEY_CTX_set_rsa_padding(m_ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
			{
				break;
			}
			if (EVP_PKEY_decrypt(m_ctx, NULL, &outlen, (const unsigned char*)inData.data(), inData.length()) <= 0)
			{
				break;
			}
			std::vector<unsigned char> out(outlen, 0);
			if (EVP_PKEY_decrypt(m_ctx, out.data(), &outlen, (const unsigned char*)inData.data(), inData.length()) <= 0)
			{
				break;
			}
			outData.append((const char*)out.data(), outlen);
			return true;
		} while (false);
		return false;
	}

	bool PKey::SealInit()
	{
		return false;
	}

	//bool PKey::SignInit()
	//{
	//	// ³É¹¦·µ»Ø1
	//	//int EVP_SignInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
	//	//int EVP_SignUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt);
	//	//int EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *sig, unsigned int *s, EVP_PKEY *pkey);

	//	//void EVP_SignInit(EVP_MD_CTX *ctx, const EVP_MD *type);
	//	EVP_SignInit();
	//	return false;
	//}
	//bool PKey::SignUpdate()
	//{
	//	EVP_SignUpdate();
	//	return false;
	//}
	//bool PKey::SignFinal()
	//{
	//	EVP_SignFinal();
	//	return false;
	//}
	//bool PKey::VerifyInit()
	//{
	//	// suc 1
	//	//int EVP_VerifyInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
	//	//int EVP_VerifyUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt);
	//	//int EVP_VerifyFinal(EVP_MD_CTX *ctx, unsigned char *sigbuf, unsigned int siglen,
	//	//	EVP_PKEY *pkey);

	//	//int EVP_VerifyInit(EVP_MD_CTX *ctx, const EVP_MD *type);
	//	return false;
	//}
	//bool PKey::VerifyUpdate()
	//{
	//	return false;
	//}
	//bool PKey::VerifyFinal()
	//{
	//	return false;
	//}


};

