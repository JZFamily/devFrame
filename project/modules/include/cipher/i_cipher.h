//////////////////////////////////////////////////////////////////////////////////
///
///
///
///
///
/////////////////////////////////////////////////////////////////////////////////

#include <string>
#include <iostream>
#ifndef __I_HASHLIB_
#define __I_HASHLIB_

#if WIN32

#ifdef DLL_EXPORT_HASHLIB
#define DLL_API __declspec(dllexport)
#else
#define DLL_API __declspec(dllimport)
#endif // DLL_EXPORT

#endif // 

class DLL_API ICipher
{
public:
	virtual ~ICipher() {};

public:

	virtual int GetNid() const = 0;
	virtual int GetBlockSize() const = 0;
	virtual int GetKeyLength() const = 0;
	virtual int GetIVLength() const = 0;
	virtual int GetMode() const = 0;

public:

	///@func	: InIt
	///@param	: secretKeys ������Կ
	///@param	: isEncrypt ����=1  ����=0  ��һ�ε�ֵ=-1
	virtual bool Init(const std::string& data, int isEncrypt = 1) = 0;

	///@func	: Update ���������indata, ׷�ӵ�outData
	///@param	: inData ��������
	///@param	: outData ��������
	virtual int  Update(const std::string& inData, std::string& outData) = 0;

	///@func	: Update ���������indata, ׷�ӵ�outData
	///@param	: inData ��������
	///@param	: outData ��������
	virtual int  Update(const char * inData, const int& inLen, std::string& outData) = 0;

	///@func	: Update ���������indata, ׷�ӵ�outData
	///@param	: inData ��������
	///@param	: outData ��������
	virtual int  Update(std::istream& iStream, std::ostream& oStream) = 0;

	///@func	: Final ׷�ӵ�outData
	///@param	: outData ��������
	///@param	: toleratePadding �Ƿ�����padding
	virtual int  Final(std::string& outData, bool toleratePadding = false) = 0;

	///@func	: Final ׷�ӵ�outData
	///@param	: outData ��������
	///@param	: toleratePadding �Ƿ�����padding
	virtual int  Final(std::ostream& oStream, bool toleratePadding = false) = 0;
};

extern "C" DLL_API  ICipher * createCipher(const std::string&);
extern "C" DLL_API  void releaseCipher(ICipher *p);

#ifndef DLL_EXPORT_HASHLIB
#include <memory>
#include <functional>

inline std::unique_ptr<ICipher, std::function<void(ICipher*)>> getCipher(const std::string& cipherName)
{
	return std::unique_ptr<ICipher, std::function<void(ICipher*)>>(createCipher(cipherName), releaseCipher);
};
#endif

#endif // !__I_HASHLIB_
