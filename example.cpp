
#include "openfhe.h"

using namespace lbcrypto;

int main() {
    
    uint32_t multDepth = 2;

    
    uint32_t scaleModSize = 50;


    uint32_t batchSize = 1;
    
    
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    //std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

    
    auto keys = cc->KeyGen();

 
    cc->EvalMultKeyGen(keys.secretKey);

    double myInput[5];
    std::cout<<"Please input 5 numbers: ";
    for(int i = 0; i < 5; i++)
    	std::cin >> myInput[i];
   
    
    std::vector<double> x[5];
    
    for(int i = 0; i < 5; i = i + 1){
    	x[i].push_back(myInput[i]);
    }
   
	Plaintext ptxt[5];
	
    for(int i = 0;i < 5;i++)
    	ptxt[i] = cc->MakeCKKSPackedPlaintext(x[i]);
   
    for(int i = 0; i < 5; i++){
	std::cout << "Input x"<< i << " " << ptxt[i] <<std::endl;
    }
    
    auto cipher = cc->Encrypt(keys.publicKey, ptxt[0]);
    for(int i = 1; i < 5; i++){
    	auto cipher2 = cc -> Encrypt(keys.publicKey, ptxt[i]);
    	cipher = cc->EvalAdd(cipher, cipher2);
    }
    cipher = cc->EvalMult(cipher, 0.2);
   
    Plaintext result;
   
    std::cout.precision(8);

    std::cout << std::endl << "Results of homomorphic computations: " << std::endl;

		cc->Decrypt(keys.secretKey, cipher, &result);
    		result->SetLength(batchSize);
    		std::cout<<"result " << " " << result << std::endl;
    
    return 0;
}
