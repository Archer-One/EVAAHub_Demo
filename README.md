# EVAAHub_Demo
## Abstract
Blockchain technology has played a pivotal role in the global adoption of cryptocurrencies like Bitcoin. However, scalability and privacy limitations continue to hinder broader progress. The Payment Channel Network (PCN) presents a promising solution by enabling fast off-chain payments between parties through intermediate nodes. Despite its potential, existing PCN solutions often suffer from one or more of the following drawbacks: they either support only fixed payment amounts, rely heavily on the anonymity of underlying blockchains (e.g., ZCash), or provide limited privacy and functionality. BlindHub is an exception, but its inefficiency—manifested in a 17-second processing time and 87,860 KB per transaction—limits its practical applicability.

To address these challenges, we propose a new PCN scheme, $\evaahub$, which integrates two key components: the Double-Blind Signature ($\dbsign$) and the Double-Base Zero-Knowledge Range Argument ($\dbzkra$). The $\dbsign$ component introduces a new cryptographic primitive that performs double blinding of messages, enabling off-chain transactions with variable amounts while preserving both the payment relationship and amounts involved. Meanwhile, the $\dbzkra$ component ensures the validity of blinded transaction amounts to the intermediate node, without compromising efficiency. A thorough security analysis within the Universal Composability framework demonstrates that $\evaahub$ achieves atomicity, relationship anonymity, value privacy, and balance security. Extensive experimental results further show that $\evaahub$ outperforms BlindHub, achieving a 3,682-fold reduction in communication costs and a 306-fold improvement in computational efficiency.

## Testbed
- unbuntu 18.04
- c++
- pbc
  
