//////////////////////////////////////////////////////////////////////////////////
///
///
///
///
///
/////////////////////////////////////////////////////////////////////////////////

#include <string>

#ifndef __I_PKEY_
#define __I_PKEY_

#if WIN32

#ifdef DLL_EXPORT_PKEY
#define DLL_API __declspec(dllexport)
#else
#define DLL_API __declspec(dllimport)
#endif // DLL_EXPORT

#endif // 


class DLL_API IPKey
{
public:
	virtual ~IPKey() {};
public:
	virtual bool Genkey(int rsabits = 2048) = 0;
	virtual bool LoadPublicKey(const std::string& fullpath) = 0;
	virtual bool LoadPrivateKey(const std::string& fullpath) = 0;
	virtual bool SavePublicKey(const std::string& fullpath) = 0;
	virtual bool SavePrivateKey(const std::string& fullpath) = 0;
public:
	//私钥签名
	virtual bool Sign(const std::string& indata, std::string& outData, const std::string& mdTpye = "md5") = 0;
	virtual bool Sign(std::istream& iStream, std::string& outData, const std::string& mdTpye = "md5") = 0;

	//公钥验证
	virtual bool Verify(const std::string& data, const std::string& sigData, const std::string& mdTpye = "md5") = 0;
	virtual bool Verify(std::istream& iStream, const std::string& sigData, const std::string& mdTpye = "md5") = 0;

	//公钥加密
	virtual bool Encrypt(const std::string& inData, std::string& outData) = 0;
	//私钥解密
	virtual bool Decrypt(const std::string& inData, std::string& outData) = 0;

	virtual bool SealInit() = 0;
		
	//virtual bool SignInit() = 0;
	//virtual bool SignUpdate() = 0;
	//virtual bool SignFinal() = 0;
	//virtual bool VerifyInit() = 0;
	//virtual bool VerifyUpdate() = 0;
	//virtual bool VerifyFinal() = 0;
};

extern "C" DLL_API IPKey * createPKey(const std::string & pkeyName);
extern "C" DLL_API void releasePKey(IPKey *p);

#ifndef DLL_EXPORT_PKEY
#include <memory>
#include <functional>

inline std::unique_ptr<IPKey, std::function<void(IPKey*)>> getPKey()
{
	return std::unique_ptr<IPKey, std::function<void(IPKey*)>>(createPKey(), releasePKey);
};
#endif

#endif // !__I_PKEY_
