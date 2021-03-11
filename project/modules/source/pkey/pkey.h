
//////////////////////////////////////////////////////////////////////////////////
///@auther	:jzf
///@date	:2021-02-10	
///@description:
///
///@version:  
///		v0.2.10,暂时只支持RSA
/////////////////////////////////////////////////////////////////////////////////
#include "pkey/i_pkey.h"
#include <unordered_map>
#ifndef __PKEY_
#define __PKEY_

namespace pkey {

	class PKey: public IPKey
	{
	public:
		PKey() = delete;
		PKey(const PKey&) = delete;
		PKey(int pkeyNid);
		virtual ~PKey();
	public:
		virtual bool Genkey(int rsabits = 2048);
		virtual bool LoadPublicKey(const std::string& fullpath);
		virtual bool LoadPrivateKey(const std::string& fullpath);
		virtual bool SavePublicKey(const std::string& fullpath);
		virtual bool SavePrivateKey(const std::string& fullpath);
	public:
		//virtual bool SignInit();
		//virtual bool SignUpdate();
		//virtual bool SignFinal();
		//virtual bool VerifyInit();
		//virtual bool VerifyUpdate();
		//virtual bool VerifyFinal();
		virtual bool Sign(const std::string& indata, std::string& outData, const std::string& mdTpye = "md5") ;
		virtual bool Verify(const std::string& data, const std::string& sigData, const std::string& mdTpye = "md5");
		virtual bool Sign(std::istream& iStream, std::string& outData, const std::string& mdTpye = "md5") ;
		virtual bool Verify(std::istream& iStream, const std::string& sigData, const std::string& mdTpye = "md5") ;

		//公钥加密
		virtual bool Encrypt(const std::string& inData, std::string& outData) override;
		//私钥解密
		virtual bool Decrypt(const std::string& inData, std::string& outData) override;

		virtual bool SealInit() ;
		
		static IPKey *createPkey(const std::string& pkeyName);
	private:
		static std::unordered_map<std::string, const int> PKey::pkeyname2nid;
		
	private:
		
		EVP_PKEY_CTX*	m_ctx;
		EVP_CIPHER_CTX*	m_cipherCtx;
		EVP_PKEY*		m_pkey;
		int				m_pkeyNid;
	};

}
#endif // !__PKEY_