
#include "cipher/i_cipher.h"

#ifndef __CIPHER_
#define __CIPHER_

namespace cipher {

class Cipher :public ICipher
{
public:
	Cipher(const std::string& cipherName);
	Cipher(const Cipher&) = delete;
	virtual ~Cipher();

public:
	
	///@funcname: InIt
	///@param	: secretKeys 明文密钥
	///@param	: isEncrypt 加密=1  解密=0  上一次的值=-1
	virtual bool Init(const std::string& secretKeys,int isEncrypt = 1);

	///@func	: Update 加密输入的indata, 追加到outData
	///@param	: inData 明文数据
	///@param	: outData 密文数据
	virtual int Update(const std::string& inData, std::string& outData);


	///@func	: Update 加密输入的indata, 追加到outData
	///@param	: inData 明文数据
	///@param	: outData 密文数据
	virtual int  Update(const char * inData, const int& inLen, std::string& outData);

	///@func	: Update 加密输入的indata, 追加到outData
	///@param	: inData 明文数据
	///@param	: outData 密文数据
	virtual int  Update(std::istream& iStream, std::ostream& oStream);

	virtual int Final(std::string& outData, bool toleratePadding = false);

	virtual int Final(std::ostream& oStream, bool toleratePadding = false);

public:
	virtual int GetNid() const;
	virtual int GetBlockSize() const;
	virtual int GetKeyLength() const;
	virtual int GetIVLength() const;
	virtual int GetMode() const;

private:
	const EVP_CIPHER*	m_cipher;
	EVP_CIPHER_CTX*		m_ctx;
	std::string			m_cipherName;
};

}
#endif // !__CIPHER_