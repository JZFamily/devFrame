#include "openssl/evp.h"
#include "hashlib.h"
#include <sstream>
#include <vector>

extern "C"
{
	IHashLib * createHashLib(const DigestType& type)
	{
		hashlib::HashLib* phashlib = new hashlib::HashLib(type);
		if (phashlib == nullptr)
		{
			return phashlib;
		}

		if (!phashlib->init())
		{
			delete  phashlib;
			return nullptr;
		}
		return phashlib;
	}
	void releaseHashLib(IHashLib *p)
	{
		delete p;
	}
}

namespace hashlib {

	constexpr int MD5_DIGEST_LENGTH = 16; 
	constexpr int SHA1_DIGEST_LENGTH = 20;
	constexpr int SHA224_DIGEST_LENGTH = 28;
	constexpr int SHA256_DIGEST_LENGTH = 32;
	constexpr int SHA384_DIGEST_LENGTH = 48;
	constexpr int SHA512_DIGEST_LENGTH = 64;

	std::unordered_map<DigestType, const int> HashLib::mdtype2len = {
		{MD_MD5,MD5_DIGEST_LENGTH},
		{MD_SHA1,SHA1_DIGEST_LENGTH},
		{MD_SHA224,SHA224_DIGEST_LENGTH},
		{MD_SHA256,SHA256_DIGEST_LENGTH},
		{MD_SHA384,SHA384_DIGEST_LENGTH},
		{MD_SHA512,SHA512_DIGEST_LENGTH} };

		//# define MD5_DIGEST_LENGTH 16
		//# define SHA1_DIGEST_LENGTH 20
		//# define SHA224_DIGEST_LENGTH    28
		//# define SHA256_DIGEST_LENGTH    32
		//# define SHA384_DIGEST_LENGTH    48
		//# define SHA512_DIGEST_LENGTH    64

	HashLib::HashLib()
		:m_digestType(MD_MD5)
		, m_blockSize(1024)
		, m_pMdCtx(nullptr)
	{
		m_pMdCtx = EVP_MD_CTX_create();
		if (m_pMdCtx == nullptr)
		{
			throw std::runtime_error("create ctx failed!");
		}
		EVP_MD_CTX_init(m_pMdCtx);
	}

	HashLib::HashLib(const DigestType & type)
		:m_digestType(type)
		, m_blockSize(1024)
		, m_pMdCtx(nullptr)
	{
		m_pMdCtx = EVP_MD_CTX_create();
		if (m_pMdCtx == nullptr)
		{
			throw std::runtime_error("create ctx failed!");
		}
		EVP_MD_CTX_init(m_pMdCtx);
	}

	HashLib::~HashLib()
	{
		if (m_pMdCtx != nullptr)
		{
			EVP_MD_CTX_destroy(m_pMdCtx);
		}
	}

	const int HashLib::getDigestSize() const
	{
		return static_cast<int>(m_disgest.length());
	}

	const uint32_t HashLib::getBlockSize() const
	{
		// TODO: 在此处插入 return 语句
		return m_blockSize;
	}

	void HashLib::setBlockSize(const uint32_t & blkSize)
	{
		if (blkSize == 0)
		{
			return;
		}
		m_blockSize = blkSize;
	}

	const DigestType & HashLib::getType() const
	{
		// TODO: 在此处插入 return 语句
		return m_digestType;
	}

	void HashLib::setType(const DigestType & type)
	{
		m_digestType = type;
	}

	bool HashLib::init()
	{
		switch (m_digestType)
		{
		case MD_MD5:
		{
			EVP_DigestInit(m_pMdCtx, EVP_md5());
		}
		break;
		case MD_SHA1:
		{
			EVP_DigestInit(m_pMdCtx, EVP_sha1());
		}
		break;
		case MD_SHA224:
		{
			EVP_DigestInit(m_pMdCtx, EVP_sha224());
		}
		break;
		case MD_SHA256:
		{
			EVP_DigestInit(m_pMdCtx, EVP_sha256());
		}
		break;
		case MD_SHA384:
		{
			EVP_DigestInit(m_pMdCtx, EVP_sha384());
		}
		break;
		case MD_SHA512:
		{
			EVP_DigestInit(m_pMdCtx, EVP_sha512());
		}
		break;
		case MD_SM3:
		{
			//EVP_DigestInit(m_pMdCtx, EVP_sha384());
			throw std::logic_error("not impl!");
		}
		break;
		default:
			return false;
			break;
		}

		return true;
	}

	int HashLib::update(const std::string & data)
	{
		m_disgest.clear();
		return EVP_DigestUpdate(m_pMdCtx, data.data(), data.length());;
	}

	bool HashLib::digest(std::string & digest)
	{
		if (m_disgest.empty() && !genDigest())
		{
			return "";
		}
		digest = m_disgest;
		return true;
	}

	std::string HashLib::hexdigest()
	{
		if (m_disgest.empty() && !genDigest())
		{
			return "";
		}
		//OPENSSL_hexstr2buf
		std::stringstream ss;
		for (auto& item : m_disgest)
		{
			ss.flags(std::ios::hex| std::ios::right |std::ios::internal);
			ss.width(2);
			ss.fill('0');
			ss << (uint32_t)(uint8_t)item;
		}
		return ss.str();
	}

	bool HashLib::copy(std::string & digest)
	{
		if (m_disgest.empty() && !genDigest())
		{
			return "";
		}
		digest = m_disgest;
		return true;
	}

	bool HashLib::genDigest()
	{
		EVP_MD_CTX *pMdCtx = EVP_MD_CTX_create();
		if (pMdCtx == nullptr || m_pMdCtx == nullptr)
		{
			return false;
		}
		EVP_MD_CTX_copy(pMdCtx, m_pMdCtx);
		std::vector<unsigned char> md(mdtype2len[m_digestType], 0);
		unsigned int s;
		EVP_DigestFinal(pMdCtx, md.data(), &s);
		EVP_MD_CTX_destroy(pMdCtx);
		m_disgest.append((const char*)md.data(), s);
		return true;
	}
};

