//////////////////////////////////////////////////////////////////////////////////
///
///
///
///
///
/////////////////////////////////////////////////////////////////////////////////

#include <string>

#ifndef __I_HASHLIB_
#define __I_HASHLIB_

#if WIN32

#ifdef DLL_EXPORT_HASHLIB
#define DLL_API __declspec(dllexport)
#else
#define DLL_API __declspec(dllimport)
#endif // DLL_EXPORT

#endif // 

enum DigestType
{
	MD_MD5 = 0,
	MD_SHA1, //以前常用，已过时
	MD_SHA224,
	MD_SHA256,	//使用广泛
	MD_SHA384,
	MD_SHA512,
	MD_SM3,		//国标
	HMAC_SHA256

};

class DLL_API IHashLib
{
public:
	virtual ~IHashLib() {};
public:
	virtual const int getDigestSize() const = 0;
	
	virtual const uint32_t getBlockSize() const = 0;
	//virtual void setBlockSize(const uint32_t& blkSize) = 0;

	virtual const DigestType& getType() const = 0;
	//virtual void setType(const DigestType& type) = 0;
	
public:
	virtual int update(const std::string& data) = 0;
	virtual bool digest(std::string& digest) = 0;
	virtual std::string hexdigest() = 0;
	virtual bool copy(std::string& digest) = 0;
};

extern "C" DLL_API IHashLib * createHashLib(const DigestType&);
extern "C" DLL_API void releaseHashLib(IHashLib *p);

#ifndef DLL_EXPORT_HASHLIB
#include <memory>
#include <functional>

inline std::unique_ptr<IHashLib, std::function<void(IHashLib*)>> getHashLib(const DigestType& type = MD_MD5)
{
	return std::unique_ptr<IHashLib, std::function<void(IHashLib*)>>(createHashLib(MD_MD5), releaseHashLib);;
};
#endif

#endif // !__I_HASHLIB_
