
#include "hashlib/i_hashlib.h"
#include <unordered_map>
#ifndef __HASHLIB_
#define __HASHLIB_


namespace hashlib {

class HashLib :public IHashLib
{
public:
	HashLib();
	HashLib(const DigestType& type);
	HashLib(const HashLib&) = delete;
	virtual ~HashLib();
public:
	virtual const int getDigestSize() const;

	virtual const uint32_t getBlockSize() const;
	virtual void setBlockSize(const uint32_t& blkSize);


	virtual const DigestType& getType() const;
	virtual void setType(const DigestType& type);
	
public:
	bool init();
	virtual int update(const std::string& data);
	virtual bool digest(std::string& digest);
	virtual std::string hexdigest();
	virtual bool copy(std::string& digest);
private:
	bool genDigest();
private:
	static std::unordered_map<DigestType, const int> mdtype2len;
private:
	DigestType m_digestType;
	std::string m_disgest;
	int m_blockSize;
	EVP_MD_CTX* m_pMdCtx;
};

}
#endif // !__HASHLIB_