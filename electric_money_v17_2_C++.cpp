#include <openssl/params.h>
#include <openssl/core_names.h>
#include <functional>
#include <cctype>
// Electric Money V17.2 Post-Quantum — C++17 consensus/reference port (hardened)
// Derived from electric_money_v17_C++.cpp with critical security/robustness fixes.
// NOT production/mainnet cryptocurrency software.
// Requires OpenSSL 3.5+ (ML-DSA-65) and json-c.
// Build: g++ -std=c++17 -O2 -pthread electric_money_v17_1_fixed.cpp -lcrypto -ljson-c -o electric_money
//
// Critical fixes vs original v17 C++ and V17.1:
// - Annual wallet tax: at most ONE cycle per wallet per block (DoS fix)
// - Difficulty retarget interval raised from 10 -> 144 blocks (~1 day)
// - Protocol/network identifiers updated
// - Safer cycle bounding and clearer comments
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <json-c/json.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <limits>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <boost/multiprecision/cpp_int.hpp>
using i64 = std::int64_t;
using u64 = std::uint64_t;
using boost::multiprecision::cpp_int;
static constexpr i64 COIN=100000000;
static constexpr i64 MAX_SUPPLY=7227002484100600LL;
static constexpr i64 BASE_REWARD=25*COIN;
static constexpr i64 INITIAL_BLOCK_REWARD=25*COIN;
static constexpr int HALVING_INTERVAL=1445400;
static constexpr int TX_BURN_BPS=5;
static constexpr int RECEIVER_TAX_BPS=20;
static constexpr int TARGET_BLOCK_TIME=600;
static constexpr int MONTH_SECONDS=30*24*60*60;
static constexpr int YEAR_SECONDS=365*24*60*60;
static constexpr int MINER_REWARD_EPOCH_BLOCKS=MONTH_SECONDS/TARGET_BLOCK_TIME;
static constexpr int DIFFICULTY_INTERVAL=144;  // V17.1: ~1 day (was 10)
static constexpr int GENESIS_DIFFICULTY=2;
static constexpr int MIN_DIFFICULTY=1;
static constexpr int MAX_DIFFICULTY=32;
static constexpr int MAX_FUTURE_BLOCK_TIME=120;
static constexpr int MAX_TX_AGE=24*60*60;
static constexpr i64 MAX_TX_AMOUNT=MAX_SUPPLY;
static constexpr int MAX_TX_PER_BLOCK=5000;
static constexpr size_t MAX_BLOCK_BYTES=2*1024*1024;
static constexpr int MTP_WINDOW=11;
static constexpr int PROTOCOL_VERSION=17; // consensus protocol family; V17.2 is a hardened patch release
static constexpr int MLDSA65_PUBLIC_KEY_BYTES=1952;
static constexpr int MLDSA65_SIGNATURE_BYTES=3309;
static constexpr size_t MAX_FRAME_BYTES=16*1024*1024;
static constexpr int MAX_ORPHANS=2048;
static constexpr int MAX_PEERS=64;
static constexpr int MINING_SHARE_MIN_DIFFICULTY=1;
static constexpr int SHARE_DIFFICULTY_OFFSET=1;
static constexpr int MAX_SHARES_PER_BLOCK=256;
static constexpr int MAX_PENDING_SHARES=20000;
static constexpr int MAX_TAX_CYCLES_PER_BLOCK=1;  // V17.1: max annual tax cycles per wallet per block
static constexpr int MAX_SEEN=50000;
static const std::string NETWORK_ID="ELECTRIC-MONEY-TESTNET-V17-PQ-HARDENED-2";
static const std::string PQ_ALG="ML-DSA-65";
static const std::string ZERO_HASH(128,'0');
static const std::string L2_BRIDGE_ADDRESS="EM_L2_BRIDGE";
static const std::string TREASURY_ADDRESS="ELECTRIC_MONEY_TREASURY";
static const std::string GENESIS_HASH="00c5997a54747344d26e5f375e1cb95c2298c046003d85473e30486c2ac5cd0f630c8e31f0c64c8224401bbc9bef04cb91ab8a08d227d4d46c0bc2d844c8c4f0";
static const std::string GENESIS_MERKLE="befa9c9f23413acb76d5c7fe6dd70967293f0f60f5c87f5a849d077bbf05338b901d213003930b1b4f988a9cd2eff1da81859e52fadac3f53b20438f269c609b";
static constexpr u64 GENESIS_NONCE=372;
static const std::string GENESIS_MESSAGE="ELECTRIC MONEY - Genesis Block. Utility protocol with 0.25% incoming payment levy (0.20% Treasury + 0.05% burn), 0.25% annual wallet balance levy (0.20% Treasury + 0.05% burn), and 72,270,024.841006 EM maximum cumulative issuance.";
static i64 now_s() {
    return (i64)std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
static std::string hex(const unsigned char*p,size_t n) {
    static const char*h="0123456789abcdef";
    std::string s;
    s.resize(n*2);
    for(size_t i=0;i<n;i++) {
        s[2*i]=h[p[i]>>4];
        s[2*i+1]=h[p[i]&15];
    }
    return s;
}
static std::vector<unsigned char> unhex(const std::string&s) {
    if(s.size()%2)throw std::runtime_error("odd hex");
    std::vector<unsigned char>v(s.size()/2);
    for(size_t i=0;i<v.size();i++) {
        auto cv=[](char c)->int {
            if(c>='0'&&c<='9')return c-'0';
            if(c>='a'&&c<='f')return c-'a'+10;
            if(c>='A'&&c<='F')return c-'A'+10;
            return -1;
        };
        int a=cv(s[2*i]),b=cv(s[2*i+1]);
        if(a<0||b<0)throw std::runtime_error("bad hex");
        v[i]=(a<<4)|b;
    }
    return v;
}
static std::string json_escape(const std::string&s) {
    std::ostringstream o;
    o<<'"';
    for(unsigned char c:s) {
        switch(c) {
            case '"':o<<"\\\"";
            break;
            case '\\':o<<"\\\\";
            break;
            case '\b':o<<"\\b";
            break;
            case '\f':o<<"\\f";
            break;
            case '\n':o<<"\\n";
            break;
            case '\r':o<<"\\r";
            break;
            case '\t':o<<"\\t";
            break;
            default: if(c<0x20)o<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<(int)c<<std::dec<<std::setfill(' ');
            else o<<c;
        }
    }
    o<<'"';
    return o.str();
}
static std::string sha3_512(const std::string&s) {
    EVP_MD_CTX*c=EVP_MD_CTX_new();
    if(!c)throw std::runtime_error("EVP_MD_CTX");
    if(EVP_DigestInit_ex(c,EVP_sha3_512(),nullptr)<=0||EVP_DigestUpdate(c,s.data(),s.size())<=0)throw std::runtime_error("SHA3 init");
    unsigned char out[64];
    unsigned int n=0;
    if(EVP_DigestFinal_ex(c,out,&n)<=0) {
        EVP_MD_CTX_free(c);
        throw std::runtime_error("SHA3 final");
    }
    EVP_MD_CTX_free(c);
    return hex(out,n);
}
static std::string canonical(const std::map<std::string,std::string>&raw) {
    std::ostringstream o;
    o<<'{';
    bool first=true;
    for(auto&[k,v]:raw) {
        if(!first)o<<',';
        first=false;
        o<<json_escape(k)<<':'<<v;
    }
    o<<'}';
    return o.str();
}
static std::string hash_obj(const std::map<std::string,std::string>&m) {
    return sha3_512(canonical(m));
}
static bool is_hex(const std::string&s,size_t len) {
    if(s.size()!=len)return false;
    for(char c:s)if(!std::isxdigit((unsigned char)c))return false;
    return true;
}
static bool json_get_string(json_object*o,const char*k,std::string&out) {
    json_object*v=nullptr;
    if(!o || !json_object_is_type(o,json_type_object) || !json_object_object_get_ex(o,k,&v) || !v || !json_object_is_type(v,json_type_string)) return false;
    out=json_object_get_string(v);
    return true;
}
static bool json_get_i64(json_object*o,const char*k,i64&out) {
    json_object*v=nullptr;
    if(!o || !json_object_is_type(o,json_type_object) || !json_object_object_get_ex(o,k,&v) || !v || !json_object_is_type(v,json_type_int)) return false;
    out=json_object_get_int64(v);
    return true;
}
static bool json_get_u64(json_object*o,const char*k,u64&out) {
    json_object*v=nullptr;
    if(!o || !json_object_is_type(o,json_type_object) || !json_object_object_get_ex(o,k,&v) || !v || !json_object_is_type(v,json_type_int)) return false;
    int64_t x=json_object_get_int64(v);
    if(x<0) return false;
    out=static_cast<u64>(x);
    return true;
}
static bool json_get_int(json_object*o,const char*k,int&out) {
    i64 x=0;
    if(!json_get_i64(o,k,x) || x<INT_MIN || x>INT_MAX) return false;
    out=static_cast<int>(x);
    return true;
}

static i64 checked_amount(i64 x) {
    if(x<=0||x>MAX_TX_AMOUNT)throw std::runtime_error("amount outside allowed range");
    return x;
}
class Wallet {
    EVP_PKEY*pkey=nullptr;
    public:
    static constexpr size_t PUB_HEX=MLDSA65_PUBLIC_KEY_BYTES*2;
    static constexpr size_t SIG_HEX=MLDSA65_SIGNATURE_BYTES*2;
    std::string public_key_hex,address;
    Wallet() {
        EVP_PKEY_CTX*c=EVP_PKEY_CTX_new_from_name(nullptr,PQ_ALG.c_str(),nullptr);
        if(!c)throw std::runtime_error("OpenSSL 3.5+ ML-DSA-65 unavailable");
        if(EVP_PKEY_keygen_init(c)<=0||EVP_PKEY_keygen(c,&pkey)<=0) {
            EVP_PKEY_CTX_free(c);
            throw std::runtime_error("ML-DSA keygen failed");
        }
        EVP_PKEY_CTX_free(c);
        size_t n=0;
        if(EVP_PKEY_get_raw_public_key(pkey,nullptr,&n)<=0||n!=MLDSA65_PUBLIC_KEY_BYTES)throw std::runtime_error("bad ML-DSA public key size");
        std::vector<unsigned char>pub(n);
        if(EVP_PKEY_get_raw_public_key(pkey,pub.data(),&n)<=0)throw std::runtime_error("public key export failed");
        public_key_hex=hex(pub.data(),pub.size());
        address=sha3_512(std::string((char*)pub.data(),pub.size()));
    }
    ~Wallet() {
        EVP_PKEY_free(pkey);
    }
    Wallet(const Wallet&)=delete;
    Wallet&operator=(const Wallet&)=delete;
    std::string sign(const std::string&msg)const {
        EVP_PKEY_CTX*c=EVP_PKEY_CTX_new_from_pkey(nullptr,pkey,nullptr);
        EVP_SIGNATURE*alg=EVP_SIGNATURE_fetch(nullptr,"ML-DSA-65",nullptr);
        if(!c||!alg)throw std::runtime_error("ML-DSA sign setup");
        if(EVP_PKEY_sign_message_init(c,alg,nullptr)<=0) {
            EVP_PKEY_CTX_free(c);
            EVP_SIGNATURE_free(alg);
            throw std::runtime_error("ML-DSA sign init");
        }
        size_t n=0;
        if(EVP_PKEY_sign(c,nullptr,&n,(const unsigned char*)msg.data(),msg.size())<=0||n!=MLDSA65_SIGNATURE_BYTES) {
            EVP_PKEY_CTX_free(c);
            EVP_SIGNATURE_free(alg);
            throw std::runtime_error("ML-DSA signature size");
        }
        std::vector<unsigned char>s(n);
        if(EVP_PKEY_sign(c,s.data(),&n,(const unsigned char*)msg.data(),msg.size())<=0) {
            EVP_PKEY_CTX_free(c);
            EVP_SIGNATURE_free(alg);
            throw std::runtime_error("ML-DSA sign");
        }
        EVP_PKEY_CTX_free(c);
        EVP_SIGNATURE_free(alg);
        return hex(s.data(),n);
    }
    static bool verify(const std::string&pubhex,const std::string&msg,const std::string&sighex) {
        try {
            if(!is_hex(pubhex,PUB_HEX)||!is_hex(sighex,SIG_HEX))return false;
            auto pub=unhex(pubhex),sig=unhex(sighex);
            EVP_PKEY_CTX*c=EVP_PKEY_CTX_new_from_name(nullptr,PQ_ALG.c_str(),nullptr);
            if(!c)return false;
            if(EVP_PKEY_fromdata_init(c)<=0)return false;
            OSSL_PARAM params[2];
            params[0]=OSSL_PARAM_construct_octet_string("pub",pub.data(),pub.size());
            params[1]=OSSL_PARAM_construct_end();
            EVP_PKEY*pk=nullptr;
            if(EVP_PKEY_fromdata(c,&pk,EVP_PKEY_PUBLIC_KEY,params)<=0) {
                EVP_PKEY_CTX_free(c);
                return false;
            }
            EVP_PKEY_CTX_free(c);
            EVP_SIGNATURE*alg=EVP_SIGNATURE_fetch(nullptr,"ML-DSA-65",nullptr);
            c=EVP_PKEY_CTX_new_from_pkey(nullptr,pk,nullptr);
            bool ok=false;
            if(c&&alg&&EVP_PKEY_verify_message_init(c,alg,nullptr)>0)ok=EVP_PKEY_verify(c,sig.data(),sig.size(),(const unsigned char*)msg.data(),msg.size())==1;
            EVP_PKEY_CTX_free(c);
            EVP_SIGNATURE_free(alg);
            EVP_PKEY_free(pk);
            return ok;
        } catch(...) {
            return false;
        }
    }
};
struct Transaction {
    std::string sender_pubkey,recipient,signature,tx_id;
    i64 amount=0,nonce=0,timestamp=0;
    std::string sender()const {
        return sha3_512(std::string((char*)unhex(sender_pubkey).data(),unhex(sender_pubkey).size()));
    }
    i64 burned()const {
        return (amount*TX_BURN_BPS)/10000;
    }
    i64 receiver_tax()const {
        return (amount*RECEIVER_TAX_BPS)/10000;
    }
    i64 net_amount()const {
        return amount-receiver_tax()-burned();
    }
    std::string signing_json()const {
        return canonical( {
             {
                "amount",std::to_string(amount)
            }
            , {
                "nonce",std::to_string(nonce)
            }
            , {
                "recipient",json_escape(recipient)
            }
            , {
                "sender_pubkey",json_escape(sender_pubkey)
            }
            , {
                "timestamp",std::to_string(timestamp)
            }
        }
        );
    }
    std::string id_json()const {
        return canonical( {
             {
                "amount",std::to_string(amount)
            }
            , {
                "nonce",std::to_string(nonce)
            }
            , {
                "recipient",json_escape(recipient)
            }
            , {
                "sender_pubkey",json_escape(sender_pubkey)
            }
            , {
                "signature",json_escape(signature)
            }
            , {
                "timestamp",std::to_string(timestamp)
            }
        }
        );
    }
    bool valid(i64 now=now_s(),bool age=true)const {
        if(amount<=0||amount>MAX_TX_AMOUNT||nonce<0||!is_hex(sender_pubkey,Wallet::PUB_HEX)||!is_hex(recipient,128)||recipient=="SYSTEM"||signature.empty()||!is_hex(signature,Wallet::SIG_HEX))return false;
        if(age&&(timestamp<now-MAX_TX_AGE||timestamp>now+MAX_FUTURE_BLOCK_TIME))return false;
        return tx_id==hash_obj( {
             {
                "amount",std::to_string(amount)
            }
            , {
                "nonce",std::to_string(nonce)
            }
            , {
                "recipient",json_escape(recipient)
            }
            , {
                "sender_pubkey",json_escape(sender_pubkey)
            }
            , {
                "signature",json_escape(signature)
            }
            , {
                "timestamp",std::to_string(timestamp)
            }
        }
        )&&Wallet::verify(sender_pubkey,signing_json(),signature);
    }
    std::string json()const {
        return canonical( {
             {
                "amount",std::to_string(amount)
            }
            , {
                "nonce",std::to_string(nonce)
            }
            , {
                "recipient",json_escape(recipient)
            }
            , {
                "sender_pubkey",json_escape(sender_pubkey)
            }
            , {
                "signature",json_escape(signature)
            }
            , {
                "timestamp",std::to_string(timestamp)
            }
            , {
                "tx_id",json_escape(tx_id)
            }
        }
        );
    }
};
struct MiningShare {
    std::string miner,job_id,share_hash,share_id;
    int difficulty=1;
    u64 nonce=0;
    static std::string challenge(const std::string&job,int d) {
        return sha3_512("ELECTRIC-MONEY-SHARE-"+NETWORK_ID+"-"+job+"-"+std::to_string(d));
    }
    std::string calc_hash()const {
        return sha3_512(challenge(job_id,difficulty)+miner+std::to_string(nonce));
    }
    std::string calc_id()const {
        return hash_obj( {
             {
                "difficulty",std::to_string(difficulty)
            }
            , {
                "job_id",json_escape(job_id)
            }
            , {
                "miner",json_escape(miner)
            }
            , {
                "nonce",std::to_string(nonce)
            }
            , {
                "share_hash",json_escape(share_hash)
            }
            , {
                "type",json_escape("mining_share")
            }
        }
        );
    }
    bool valid(const std::string&job,int d)const {
        return is_hex(miner,128)&&is_hex(job_id,128)&&difficulty>=1&&job_id==job&&difficulty==d&&share_hash==calc_hash()&&share_hash.rfind(std::string(difficulty,'0'),0)==0&&share_id==calc_id();
    }
    std::string json()const {
        return canonical( {
             {
                "difficulty",std::to_string(difficulty)
            }
            , {
                "job_id",json_escape(job_id)
            }
            , {
                "miner",json_escape(miner)
            }
            , {
                "nonce",std::to_string(nonce)
            }
            , {
                "share_hash",json_escape(share_hash)
            }
            , {
                "share_id",json_escape(share_id)
            }
            , {
                "type",json_escape("mining_share")
            }
        }
        );
    }
};
static i64 subsidy(int h) {
    if(h<=0)return BASE_REWARD;
    int halv=h/HALVING_INTERVAL;
    if(halv>=63)return 0;
    return INITIAL_BLOCK_REWARD>>halv;
}
static cpp_int block_work(int d) {
    return cpp_int(1) << (4*d);
}
struct Block {
    int index=0;
    std::string previous_hash,merkle_root,extra_data,block_hash;
    std::vector<std::string>transactions;
    i64 timestamp=0;
    u64 nonce=0;
    int difficulty=1;
    std::string header_json()const {
        return canonical( {
             {
                "difficulty",std::to_string(difficulty)
            }
            , {
                "extra_data",json_escape(extra_data)
            }
            , {
                "index",std::to_string(index)
            }
            , {
                "merkle_root",json_escape(merkle_root)
            }
            , {
                "nonce",std::to_string(nonce)
            }
            , {
                "previous_hash",json_escape(previous_hash)
            }
            , {
                "timestamp",std::to_string(timestamp)
            }
        }
        );
    }
    std::string calc_hash()const {
        return sha3_512(header_json());
    }
    void mine(const std::function<bool()>&stop=[]() {
        return false;
    }
    ) {
        for(;;) {
            if(stop())throw std::runtime_error("mining interrupted");
            block_hash=calc_hash();
            if(block_hash.rfind(std::string(difficulty,'0'),0)==0)return;
            ++nonce;
        }
    }
    std::string json()const {
        std::ostringstream o;
        o<<"{\"difficulty\":"<<difficulty<<",\"extra_data\":"<<json_escape(extra_data)<<",\"hash\":"<<json_escape(block_hash)<<",\"index\":"<<index<<",\"merkle_root\":"<<json_escape(merkle_root)<<",\"nonce\":"<<nonce<<",\"previous_hash\":"<<json_escape(previous_hash)<<",\"timestamp\":"<<timestamp<<",\"transactions\":[";
        for(size_t i=0;i<transactions.size();++i) {
            if(i)o<<',';
            o<<transactions[i];
        }
        o<<"]}";
        return o.str();
    }
};
static std::string merkle(const std::vector<std::string>&items) {
    if(items.empty())return sha3_512("");
    std::vector<std::string>v=items;
    while(v.size()>1) {
        if(v.size()%2)v.push_back(v.back());
        std::vector<std::string>n;
        for(size_t i=0;i<v.size();i+=2)n.push_back(sha3_512(v[i]+v[i+1]));
        v.swap(n);
    }
    return v[0];
}
class Blockchain {
    public:
    std::vector<Block>chain;
    std::map<std::string,Transaction>pending;
    std::map<std::string,Block>orphans;
    std::map<std::string,i64>balances,nonces;
    i64 total_issued=0,total_burned=0,treasury_balance=0;
    std::map<std::string,cpp_int>miner_work;
    std::map<std::string,i64>wallet_anchor;
    std::map<std::string,MiningShare>pending_shares;
    std::mutex mu;
    std::string db;
    Blockchain(std::string f="electric_money_v17.json"):db(std::move(f)) {
        if(std::filesystem::exists(db)) {
            if(!load()) throw std::runtime_error("database exists but failed validation");
        } else {
            genesis();
        }
    }
    int height()const {
        return (int)chain.size()-1;
    }
    i64 supply()const {
        return total_issued-total_burned;
    }
    cpp_int cumulative_work()const {
        cpp_int x=0;
        for(auto&b:chain)x+=block_work(b.difficulty);
        return x;
    }
    static int share_diff(int d) {
        return std::max(1,d-SHARE_DIFFICULTY_OFFSET);
    }
    static int expected_diff(const std::vector<Block>&c,int h) {
        if(h==0)return GENESIS_DIFFICULTY;
        int d=c[h-1].difficulty;
        if(h%DIFFICULTY_INTERVAL)return d;
        auto&first=c[h-DIFFICULTY_INTERVAL];
        auto&last=c[h-1];
        i64 actual=std::max<i64>(1,last.timestamp-first.timestamp),expected=(i64)TARGET_BLOCK_TIME*(DIFFICULTY_INTERVAL-1);
        if(actual<expected/2)++d;
        else if(actual>expected*2)--d;
        return std::clamp(d,MIN_DIFFICULTY,MAX_DIFFICULTY);
    }
    static i64 mtp(const std::vector<Block>&c) {
        std::vector<i64>t;
        for(int i=std::max(0,(int)c.size()-MTP_WINDOW);i<(int)c.size();++i)t.push_back(c[i].timestamp);
        std::sort(t.begin(),t.end());
        return t[t.size()/2];
    }
    void genesis() {
        std::string tid=hash_obj( {
             {
                "amount",std::to_string(BASE_REWARD)
            }
            , {
                "message",json_escape(GENESIS_MESSAGE)
            }
            , {
                "recipient",json_escape("Miner_Genesis")
            }
        }
        );
        std::string tx=canonical( {
             {
                "amount",std::to_string(BASE_REWARD)
            }
            , {
                "memo",json_escape(GENESIS_MESSAGE)
            }
            , {
                "recipient",json_escape("Miner_Genesis")
            }
            , {
                "tx_id",json_escape(tid)
            }
            , {
                "type",json_escape("genesis")
            }
        }
        );
        Block b;
        b.index=0;
        b.previous_hash=ZERO_HASH;
        b.transactions= {
            tx
        };
        b.timestamp=0;
        b.difficulty=GENESIS_DIFFICULTY;
        b.merkle_root=merkle( {
            tid
        }
        );
        b.extra_data=GENESIS_MESSAGE;
        b.mine();
        chain= {
            b
        };
        balances["Miner_Genesis"]=BASE_REWARD;
        total_issued=BASE_REWARD;
        wallet_anchor["Miner_Genesis"]=0;
        save();
    }
    static void credit(std::map<std::string,i64>&b,const std::string&a,i64 x) {
        if(x<0 || x>MAX_SUPPLY || b[a]<0 || b[a]>MAX_SUPPLY-x)throw std::runtime_error("balance overflow");
        b[a]+=x;
    }
    static void debit(std::map<std::string,i64>&b,const std::string&a,i64 x) {
        if(x<0||b[a]<x)throw std::runtime_error("insufficient balance");
        b[a]-=x;
    }
    static std::pair<i64,i64> annual_split(i64 bal) {
        return  {
            (bal*RECEIVER_TAX_BPS)/10000,(bal*TX_BURN_BPS)/10000
        };
    }
    // V17.1: apply at most MAX_TAX_CYCLES_PER_BLOCK (default 1) annual tax
    // cycle per wallet per block. Prevents multi-year DoS loops while remaining
    // deterministic. Missed years are collected gradually over subsequent blocks.
    static void annual(std::map<std::string,i64>&b,std::map<std::string,i64>&a,i64&treas,i64&burn,i64 ts) {
        for(auto&[addr,anchor0]:a) {
            i64 anchor=anchor0;
            int cycles_applied=0;
            // Avoid anchor + YEAR_SECONDS overflow. Consensus uses subtraction
            // only after establishing ts >= anchor.
            while(cycles_applied<MAX_TAX_CYCLES_PER_BLOCK && ts>=anchor && (ts-anchor)>=YEAR_SECONDS) {
                i64 bal=b[addr];
                if(bal>0) {
                    auto [tt,br]=annual_split(bal);
                    if(tt<0 || br<0 || tt>bal || br>bal-tt) throw std::runtime_error("annual tax arithmetic overflow");
                    i64 tax=tt+br;
                    if(tax>bal) throw std::runtime_error("annual tax exceeds balance");
                    b[addr]=bal-tax;
                    if(treas>MAX_SUPPLY-tt || burn>MAX_SUPPLY-br) throw std::runtime_error("annual treasury/burn overflow");
                    treas+=tt;
                    burn+=br;
                }
                if(anchor>std::numeric_limits<i64>::max()-YEAR_SECONDS) {
                    anchor=std::numeric_limits<i64>::max();
                    cycles_applied++;
                    break;
                }
                anchor+=YEAR_SECONDS;
                cycles_applied++;
            }
            anchor0=anchor;
        }
    }
    static void distribute(std::map<std::string,i64>&b,i64&treas,std::map<std::string,cpp_int>&work) {
        if(treas<=0)return;
        cpp_int total=0;
        for(auto&[m,w]:work)if(w>0)total+=w;
        if(total<=0)return;
        i64 distributed=0;
        std::pair<std::string,cpp_int>winner {
            "",-1
        };
        for(auto&[m,w]:work)if(w>0) {
            if(w>winner.second||(w==winner.second&&m<winner.first))winner= {
                m,w
            };
            cpp_int share_mp=(cpp_int(treas)*w)/total;
            i64 share=share_mp.convert_to<i64>();
            b[m]+=share;
            distributed+=share;
        }
        if(treas-distributed>0)b[winner.first]+=treas-distributed;
        treas=0;
        work.clear();
    }
    static bool apply_tx(const Transaction&t,std::map<std::string,i64>&b,std::map<std::string,i64>&n,i64&burn,i64&treas) {
        std::string s=t.sender();
        if(n[s]!=t.nonce||b[s]<t.amount||t.nonce==std::numeric_limits<i64>::max())return false;
        const i64 net=t.net_amount(), br=t.burned(), tt=t.receiver_tax();
        if(net<0 || br<0 || tt<0 || net>t.amount || br>t.amount || tt>t.amount ||
           br>MAX_SUPPLY-burn || tt>MAX_SUPPLY-treas)return false;
        debit(b,s,t.amount);
        try { credit(b,t.recipient,net); }
        catch(...) { return false; }
        n[s]=t.nonce+1;
        burn+=br;
        treas+=tt;
        return true;
    }
    bool validate_block(const Block&b,const Block&p,const std::vector<Block>&prefix,std::map<std::string,i64>bal,std::map<std::string,i64>nc,i64 issued,i64 burned,i64 treas,std::map<std::string,cpp_int>mw,std::map<std::string,i64>anchors,std::map<std::string,i64>*outbal=nullptr,std::map<std::string,i64>*outnc=nullptr,i64*outissued=nullptr,i64*outburn=nullptr,i64*outtreas=nullptr,std::map<std::string,cpp_int>*outmw=nullptr,std::map<std::string,i64>*outanchors=nullptr,i64 now=now_s())const {
        if(b.index!=p.index+1||b.previous_hash!=p.block_hash||b.difficulty<1||b.difficulty>MAX_DIFFICULTY||b.difficulty!=expected_diff(prefix,b.index)||b.timestamp<mtp(prefix)||b.timestamp>now+MAX_FUTURE_BLOCK_TIME)return false;
        if(b.transactions.empty()||b.transactions.size()>MAX_TX_PER_BLOCK+MAX_SHARES_PER_BLOCK+2||b.json().size()>MAX_BLOCK_BYTES)return false;
        std::vector<std::string>ids;
        for(auto&s:b.transactions) {
            json_object*o=json_tokener_parse(s.c_str());
            if(!o)return false;
            json_object*x=nullptr;
            std::string id;
            if(json_object_object_get_ex(o,"tx_id",&x))id=json_object_get_string(x);
            else if(json_object_object_get_ex(o,"share_id",&x))id=json_object_get_string(x);
            json_object_put(o);
            if(id.empty())return false;
            ids.push_back(id);
        }
        if(b.merkle_root!=merkle(ids)||b.calc_hash()!=b.block_hash||b.block_hash.rfind(std::string(b.difficulty,'0'),0)!=0)return false;
        json_object*r=json_tokener_parse(b.transactions.back().c_str());
        if(!r)return false;
        json_object*x=nullptr;
        if(!json_object_object_get_ex(r,"type",&x)||std::string(json_object_get_string(x))!="reward") {
            json_object_put(r);
            return false;
        }
        if(!json_object_object_get_ex(r,"recipient",&x)) {
            json_object_put(r);
            return false;
        }
        std::string miner=json_object_get_string(x);
        json_object_put(r);
        if(!is_hex(miner,128))return false;
        std::set<std::string>seen;
        int shares=0;
        i64 burn=burned;
        // Deterministic Genesis-tax anchor: the first post-genesis block starts
        // the annual-tax clock for Miner_Genesis. Never use wall-clock time here.
        if(b.index==1) {
            auto it=anchors.find("Miner_Genesis");
            if(it==anchors.end() || it->second==0) anchors["Miner_Genesis"]=b.timestamp;
        }
        for(size_t i=0;i+1<b.transactions.size();++i) {
            json_object*o=json_tokener_parse(b.transactions[i].c_str());
            if(!o)return false;
            json_object*t=nullptr;
            json_object_object_get_ex(o,"type",&t);
            std::string typ=t?json_object_get_string(t):"";
            json_object_object_get_ex(o,"tx_id",&x);
            std::string id=x?json_object_get_string(x):"";
            if(id.empty()||!seen.insert(id).second) {
                json_object_put(o);
                return false;
            }
            if(typ=="transfer") {
                Transaction q;
                if(!json_get_string(o,"sender_pubkey",q.sender_pubkey) || !json_get_string(o,"recipient",q.recipient) ||
                   !json_get_i64(o,"amount",q.amount) || !json_get_i64(o,"nonce",q.nonce) ||
                   !json_get_i64(o,"timestamp",q.timestamp) || !json_get_string(o,"signature",q.signature)) {
                    json_object_put(o); return false;
                }
                q.tx_id=id;
                if(!q.valid(b.timestamp,true)||!apply_tx(q,bal,nc,burn,treas)) {
                    json_object_put(o);
                    return false;
                }
                if(!anchors.count(q.recipient))anchors[q.recipient]=b.timestamp;
            } 
            else if(typ=="mining_share") {
                if(++shares>MAX_SHARES_PER_BLOCK) {
                    json_object_put(o);
                    return false;
                }
                MiningShare s;
                if(!json_get_string(o,"miner",s.miner) || !json_get_string(o,"job_id",s.job_id) ||
                   !json_get_int(o,"difficulty",s.difficulty) || !json_get_u64(o,"nonce",s.nonce) ||
                   !json_get_string(o,"share_hash",s.share_hash) || !json_get_string(o,"share_id",s.share_id)) {
                    json_object_put(o); return false;
                }
                if(!s.valid(p.block_hash,share_diff(p.difficulty))) {
                    json_object_put(o);
                    return false;
                }
                mw[s.miner]+=block_work(s.difficulty);
            } 
            else if(typ=="l2_commitment") {
                json_object*rr=nullptr;
                std::map<std::string,std::string>m;
                for(const char*k: {
                    "count","first_sequence","last_sequence","root","state_root"
                }
                ) {
                    if(!json_object_object_get_ex(o,k,&rr)) {
                        json_object_put(o);
                        return false;
                    }
                    const std::string key=k;
                    if(key=="count"||key=="first_sequence"||key=="last_sequence") {
                        if(!json_object_is_type(rr,json_type_int)) { json_object_put(o); return false; }
                        i64 v=json_object_get_int64(rr);
                        if(v<0) { json_object_put(o); return false; }
                        m[key]=std::to_string(v);
                    } else {
                        if(!json_object_is_type(rr,json_type_string)) { json_object_put(o); return false; }
                        std::string v=json_object_get_string(rr);
                        if(!is_hex(v,128)) { json_object_put(o); return false; }
                        m[key]=json_escape(v);
                    }
                }
                if(id!=hash_obj( {
                     {
                        "count",m["count"]
                    }
                    , {
                        "first_sequence",m["first_sequence"]
                    }
                    , {
                        "last_sequence",m["last_sequence"]
                    }
                    , {
                        "root",m["root"]
                    }
                    , {
                        "state_root",m["state_root"]
                    }
                    , {
                        "type",json_escape("l2_commitment")
                    }
                }
                )) {
                    json_object_put(o);
                    return false;
                }
            } 
            else  {
                json_object_put(o);
                return false;
            }
            json_object_put(o);
        }
        json_object*ro=json_tokener_parse(b.transactions.back().c_str());
        if(!ro || !json_object_is_type(ro,json_type_object)) { if(ro) json_object_put(ro); return false; }
        std::string rtype,recipient,rid; i64 amount=0,iss=0;
        bool reward_fields=json_get_string(ro,"type",rtype) && rtype=="reward" &&
            json_get_string(ro,"recipient",recipient) && json_get_string(ro,"tx_id",rid) &&
            json_get_i64(ro,"amount",amount) && json_get_i64(ro,"issuance",iss);
        i64 issuance=(issued>=MAX_SUPPLY)?0:std::min<i64>(subsidy(b.index),MAX_SUPPLY-issued);
        json_object_put(ro);
        if(!reward_fields || recipient!=miner) return false;
        if(issuance<0||amount!=issuance||iss!=issuance||rid!=hash_obj( {
             {
                "amount",std::to_string(issuance)
            }
            , {
                "block_index",std::to_string(b.index)
            }
            , {
                "issuance",std::to_string(issuance)
            }
            , {
                "recipient",json_escape(miner)
            }
            , {
                "type",json_escape("reward")
            }
        }
        ))return false;
        issued+=issuance;
        credit(bal,miner,issuance);
        if(!anchors.count(miner))anchors[miner]=b.timestamp;
        mw[miner]+=block_work(b.difficulty);
        annual(bal,anchors,treas,burn,b.timestamp);
        if(issued>MAX_SUPPLY||burn>issued||treas<0||burn<0)return false;
        if(b.index>0&&b.index%MINER_REWARD_EPOCH_BLOCKS==0)distribute(bal,treas,mw);
        if(outbal)*outbal=std::move(bal);
        if(outnc)*outnc=std::move(nc);
        if(outissued)*outissued=issued;
        if(outburn)*outburn=burn;
        if(outtreas)*outtreas=treas;
        if(outmw)*outmw=std::move(mw);
        if(outanchors)*outanchors=std::move(anchors);
        return true;
    }
    static bool validate_genesis(const Block&b) {
        if(b.index!=0 || b.previous_hash!=ZERO_HASH || b.timestamp!=0 || b.difficulty!=GENESIS_DIFFICULTY || b.nonce!=GENESIS_NONCE || b.extra_data!=GENESIS_MESSAGE || b.block_hash!=GENESIS_HASH || b.merkle_root!=GENESIS_MERKLE) return false;
        if(b.calc_hash()!=GENESIS_HASH || b.block_hash.rfind(std::string(GENESIS_DIFFICULTY,'0'),0)!=0) return false;
        if(b.transactions.size()!=1) return false;
        json_object*o=json_tokener_parse(b.transactions[0].c_str());
        if(!o || !json_object_is_type(o,json_type_object)) { if(o) json_object_put(o); return false; }
        std::string type,recipient,tid,memo; i64 amount=0;
        bool ok=json_get_string(o,"type",type) && type=="genesis" &&
                json_get_string(o,"recipient",recipient) && recipient=="Miner_Genesis" &&
                json_get_string(o,"tx_id",tid) && json_get_string(o,"memo",memo) && memo==GENESIS_MESSAGE &&
                json_get_i64(o,"amount",amount) && amount==BASE_REWARD;
        json_object_put(o);
        if(!ok) return false;
        std::string expected_tid=hash_obj({{"amount",std::to_string(BASE_REWARD)}, {"message",json_escape(GENESIS_MESSAGE)}, {"recipient",json_escape("Miner_Genesis")}});
        std::string expected_tx=canonical({{"amount",std::to_string(BASE_REWARD)}, {"memo",json_escape(GENESIS_MESSAGE)}, {"recipient",json_escape("Miner_Genesis")}, {"tx_id",json_escape(expected_tid)}, {"type",json_escape("genesis")}});
        return tid==expected_tid && merkle({tid})==GENESIS_MERKLE;
    }

    bool replay(const std::vector<Block>&c,std::map<std::string,i64>&ob,std::map<std::string,i64>&on,i64&oi,i64&oburn,i64&ot,std::map<std::string,cpp_int>&omw,std::map<std::string,i64>&oa)const {
        if(c.empty() || !validate_genesis(c[0]))return false;
        ob= {
             {
                 {
                    "Miner_Genesis",BASE_REWARD
                }
            }
        };
        on.clear();
        oi=BASE_REWARD;
        oburn=0;
        ot=0;
        omw.clear();
        oa= {
             {
                 {
                    "Miner_Genesis",0
                }
            }
        };
        for(size_t i=1;i<c.size();++i) {
            if(!validate_block(c[i],c[i-1],std::vector<Block>(c.begin(),c.begin()+i),ob,on,oi,oburn,ot,omw,oa,&ob,&on,&oi,&oburn,&ot,&omw,&oa))return false;
        }
        return true;
    }
    bool validate_chain(const std::vector<Block>&c)const {
        std::map<std::string,i64>b,n;
        std::map<std::string,cpp_int>m;
        std::map<std::string,i64>a;
        i64 i,br,t;
        return replay(c,b,n,i,br,t,m,a);
    }
    i64 next_nonce(const std::string&a) {
        std::lock_guard<std::mutex>g(mu);
        i64 n=nonces[a];
        for(auto&[id,t]:pending)if(t.sender()==a)n=std::max(n,t.nonce+1);
        return n;
    }
    bool add_transaction(const Transaction&t) {
        std::lock_guard<std::mutex>g(mu);
        if(pending.count(t.tx_id)||!t.valid())return false;
        std::map<std::string,i64>b=balances,n=nonces;
        std::vector<Transaction> pend;
        for(auto&[id,p]:pending) pend.push_back(p);
        std::sort(pend.begin(),pend.end(),[](const Transaction&a,const Transaction&b) {
            return std::make_tuple(a.timestamp,a.sender(),a.nonce,a.tx_id)<std::make_tuple(b.timestamp,b.sender(),b.nonce,b.tx_id);
        }
        );
        i64 dummy_burn=0,dummy_treas=0;
        for(auto&p:pend) if(p.sender()==t.sender() && p.nonce>=t.nonce) continue;
        else  {
            auto vb=b,vn=n;
            if(p.valid() && vn[p.sender()]==p.nonce && vb[p.sender()]>=p.amount) apply_tx(p,b,n,dummy_burn,dummy_treas);
        }
        if(n[t.sender()]!=t.nonce||b[t.sender()]<t.amount)return false;
        pending[t.tx_id]=t;
        save();
        return true;
    }
    Block candidate(const std::string&miner,const std::vector<std::string>&l2= {
    }
    ) {
        std::lock_guard<std::mutex>g(mu);
        Block b;
        b.index=chain.size();
        b.previous_hash=chain.back().block_hash;
        b.timestamp=std::max(now_s(),mtp(chain));
        b.difficulty=expected_diff(chain,b.index);
        b.extra_data="ELECTRIC-MONEY-PoW-"+NETWORK_ID;
        std::vector<std::string>txs;
        std::map<std::string,i64>bb=balances,nn=nonces;
        i64 burn=0,treas=0;
        std::vector<Transaction>ordered;
        for(auto&[id,t]:pending)ordered.push_back(t);
        std::sort(ordered.begin(),ordered.end(),[](const Transaction&a,const Transaction&b) {
            return std::make_tuple(a.timestamp,a.sender(),a.nonce,a.tx_id)<std::make_tuple(b.timestamp,b.sender(),b.nonce,b.tx_id);
        }
        );
        for(auto&t:ordered) {
            if(t.valid()&&nn[t.sender()]==t.nonce&&bb[t.sender()]>=t.amount&&txs.size()<MAX_TX_PER_BLOCK) {
                apply_tx(t,bb,nn,burn,treas);
                txs.push_back(canonical( {
                     {
                        "amount",std::to_string(t.amount)
                    }
                    , {
                        "nonce",std::to_string(t.nonce)
                    }
                    , {
                        "recipient",json_escape(t.recipient)
                    }
                    , {
                        "sender_pubkey",json_escape(t.sender_pubkey)
                    }
                    , {
                        "signature",json_escape(t.signature)
                    }
                    , {
                        "timestamp",std::to_string(t.timestamp)
                    }
                    , {
                        "tx_id",json_escape(t.tx_id)
                    }
                    , {
                        "type",json_escape("transfer")
                    }
                }
                ));
            }
        }
        for(auto&s:l2)txs.push_back(s);
        for(auto&[id,s]:pending_shares)if(s.valid(chain.back().block_hash,share_diff(chain.back().difficulty))&&txs.size()<MAX_TX_PER_BLOCK+MAX_SHARES_PER_BLOCK)txs.push_back(s.json());
        i64 iss=std::min<i64>(subsidy(b.index),MAX_SUPPLY-total_issued);
        std::string rid=hash_obj( {
             {
                "amount",std::to_string(iss)
            }
            , {
                "block_index",std::to_string(b.index)
            }
            , {
                "issuance",std::to_string(iss)
            }
            , {
                "recipient",json_escape(miner)
            }
            , {
                "type",json_escape("reward")
            }
        }
        );
        txs.push_back(canonical( {
             {
                "amount",std::to_string(iss)
            }
            , {
                "issuance",std::to_string(iss)
            }
            , {
                "recipient",json_escape(miner)
            }
            , {
                "tx_id",json_escape(rid)
            }
            , {
                "type",json_escape("reward")
            }
        }
        ));
        b.transactions=txs;
        std::vector<std::string>ids;
        for(auto&s:txs) {
            json_object*o=json_tokener_parse(s.c_str());
            json_object*x=nullptr;
            json_object_object_get_ex(o,"tx_id",&x);
            ids.push_back(json_object_get_string(x));
            json_object_put(o);
        }
        b.merkle_root=merkle(ids);
        return b;
    }
    Block mine_pending(const std::string&miner,const std::function<bool()>&stop=[]() {
        return false;
    }
    ) {
        Block b=candidate(miner);
        b.mine(stop);
        std::lock_guard<std::mutex>g(mu);
        std::map<std::string,i64>bb,nn,an;
        std::map<std::string,cpp_int>mw;
        i64 issued,burn,treas;
        if(!validate_block(b,chain.back(),chain,balances,nonces,total_issued,total_burned,treasury_balance,miner_work,wallet_anchor,&bb,&nn,&issued,&burn,&treas,&mw,&an))throw std::runtime_error("self-mined block rejected");
        chain.push_back(b);
        balances=std::move(bb);
        nonces=std::move(nn);
        total_issued=issued;
        total_burned=burn;
        treasury_balance=treas;
        miner_work=std::move(mw);
        wallet_anchor=std::move(an);
        for(auto it=pending.begin();it!=pending.end();) {
            bool found=false;
            for(auto&s:b.transactions)if(s.find(json_escape(it->first))!=std::string::npos)found=true;
            if(found)it=pending.erase(it);
            else ++it;
        }
        pending_shares.clear();
        save();
        return b;
    }
    bool replace_chain(const std::vector<Block>&c) {
        std::lock_guard<std::mutex>g(mu);
        if(!validate_chain(c)||cumulative(c)<=cumulative(chain))return false;
        std::map<std::string,i64>b,n;
        std::map<std::string,cpp_int>m;
        std::map<std::string,i64>a;
        i64 i,br,t;
        if(!replay(c,b,n,i,br,t,m,a))return false;
        chain=c;
        balances=b;
        nonces=n;
        total_issued=i;
        total_burned=br;
        treasury_balance=t;
        miner_work=m;
        wallet_anchor=a;
        save();
        return true;
    }
    static cpp_int cumulative(const std::vector<Block>&c) {
        cpp_int x=0;
        for(auto&b:c)x+=block_work(b.difficulty);
        return x;
    }
    void save()const {
        std::ofstream f(db+".tmp");
        if(!f)return;
        f<<"{\"network_id\":"<<json_escape(NETWORK_ID)<<",\"protocol_version\":"<<PROTOCOL_VERSION<<",\"chain\":[";
        for(size_t i=0;i<chain.size();++i) {
            if(i)f<<',';
            f<<chain[i].json();
        }
        f<<"],\"pending\":[";
        size_t k=0;
        for(auto&[id,t]:pending) {
            if(k++)f<<',';
            f<<t.json();
        }
        f<<"],\"pending_shares\":[";
        k=0;
        for(auto&[id,s]:pending_shares) {
            if(k++)f<<',';
            f<<s.json();
        }
        f<<"]}";
        f.flush();
        if(!f.good()) throw std::runtime_error("database write failed");
        f.close();
        if(std::rename((db+".tmp").c_str(),db.c_str())!=0) throw std::runtime_error("database commit failed");
    }
    bool load() {
        std::ifstream f(db);
        if(!f)return false;
        std::string s((std::istreambuf_iterator<char>(f)), {
        }
        );
        json_object*r=json_tokener_parse(s.c_str());
        if(!r || !json_object_is_type(r,json_type_object)) { if(r) json_object_put(r); return false; }
        std::string network; i64 protocol=0;
        json_object*ch=nullptr;
        if(!json_get_string(r,"network_id",network) || network!=NETWORK_ID || !json_get_i64(r,"protocol_version",protocol) || protocol!=PROTOCOL_VERSION ||
           !json_object_object_get_ex(r,"chain",&ch) || !json_object_is_type(ch,json_type_array)) {
            json_object_put(r);
            return false;
        }
        std::vector<Block>c;
        for(size_t i=0;i<json_object_array_length(ch);++i) {
            json_object*o=json_object_array_get_idx(ch,i);
            if(!o || !json_object_is_type(o,json_type_object)) { json_object_put(r); return false; }
            Block b; std::string hash; i64 idx=0,ts=0; int diff=0; u64 nonce=0;
            if(!json_get_i64(o,"index",idx) || idx<0 || idx>INT_MAX || !json_get_string(o,"previous_hash",b.previous_hash) ||
               !json_get_i64(o,"timestamp",ts) || !json_get_u64(o,"nonce",nonce) || !json_get_int(o,"difficulty",diff) ||
               !json_get_string(o,"merkle_root",b.merkle_root) || !json_get_string(o,"extra_data",b.extra_data) ||
               !json_get_string(o,"hash",hash)) { json_object_put(r); return false; }
            json_object*x=nullptr;
            if(!json_object_object_get_ex(o,"transactions",&x) || !x || !json_object_is_type(x,json_type_array)) { json_object_put(r); return false; }
            b.index=static_cast<int>(idx); b.timestamp=ts; b.nonce=nonce; b.difficulty=diff; b.block_hash=hash;
            for(size_t j=0;j<json_object_array_length(x);++j) {
                json_object*tx=json_object_array_get_idx(x,j);
                if(!tx || !json_object_is_type(tx,json_type_object)) { json_object_put(r); return false; }
                b.transactions.push_back(json_object_to_json_string(tx));
            }
            c.push_back(std::move(b));
        }
        json_object_put(r);
        std::map<std::string,i64>b,n;
        std::map<std::string,cpp_int>m;
        std::map<std::string,i64>a;
        i64 i,br,t;
        if(c.empty()||!replay(c,b,n,i,br,t,m,a))return false;
        chain=c;
        balances=b;
        nonces=n;
        total_issued=i;
        total_burned=br;
        treasury_balance=t;
        miner_work=m;
        wallet_anchor=a;
        return true;
    }
};
struct L2Transaction {
    std::string sender_pubkey,recipient,signature,tx_id;
    i64 amount=0,nonce=0,timestamp=0;
    std::string signing()const {
        return canonical( {
             {
                "amount",std::to_string(amount)
            }
            , {
                "nonce",std::to_string(nonce)
            }
            , {
                "recipient",json_escape(recipient)
            }
            , {
                "sender_pubkey",json_escape(sender_pubkey)
            }
            , {
                "timestamp",std::to_string(timestamp)
            }
        }
        );
    }
    bool valid()const {
        return amount>0&&is_hex(sender_pubkey,Wallet::PUB_HEX)&&is_hex(recipient,128)&&is_hex(signature,Wallet::SIG_HEX)&&tx_id==hash_obj( {
             {
                "amount",std::to_string(amount)
            }
            , {
                "nonce",std::to_string(nonce)
            }
            , {
                "recipient",json_escape(recipient)
            }
            , {
                "sender_pubkey",json_escape(sender_pubkey)
            }
            , {
                "signature",json_escape(signature)
            }
            , {
                "timestamp",std::to_string(timestamp)
            }
        }
        )&&Wallet::verify(sender_pubkey,signing(),signature);
    }
};
class Layer2Sequencer {
    public:std::map<std::string,i64>balances,nonces;
    std::vector<L2Transaction>mempool;
    u64 sequence=0;
    std::string poh=sha3_512("EM_L2_POH_GENESIS");
    std::vector<std::string>commitments;
    bool deposit(const std::string&a,i64 x) {
        if(x<=0 || x>MAX_SUPPLY)return false;
        if(balances[a]<0 || balances[a]>MAX_SUPPLY-x)return false;
        balances[a]+=x;
        return true;
    }
    bool add(const L2Transaction&t) {
        if(!t.valid())return false;
        std::string sender=sha3_512(std::string((char*)unhex(t.sender_pubkey).data(),unhex(t.sender_pubkey).size()));
        if(t.nonce!=nonces[sender]||balances[sender]<t.amount)return false;
        if(nonces[sender]==std::numeric_limits<i64>::max())return false;
        if(balances[t.recipient]<0 || balances[t.recipient]>MAX_SUPPLY-t.amount)return false;
        balances[sender]-=t.amount;
        balances[t.recipient]+=t.amount;
        nonces[sender]++;
        sequence++;
        poh=sha3_512(poh+t.tx_id);
        mempool.push_back(t);
        return true;
    }
    std::optional<std::string>commit() {
        if(mempool.empty())return std::nullopt;
        std::vector<std::string>ids;
        for(auto&t:mempool)ids.push_back(t.tx_id);
        std::string root=merkle(ids);
        std::ostringstream bo,no;
        bo<<"{";
         {
            bool f=true;
            for(auto&[a,v]:balances) {
                if(!f)bo<<",";
                f=false;
                bo<<json_escape(a)<<":"<<v;
            }
        }
        bo<<"}";
        no<<"{";
         {
            bool f=true;
            for(auto&[a,v]:nonces) {
                if(!f)no<<",";
                f=false;
                no<<json_escape(a)<<":"<<v;
            }
        }
        no<<"}";
        std::string sr=hash_obj( {
             {
                "balances",bo.str()
            }
            , {
                "nonces",no.str()
            }
        }
        );
        std::string c=canonical( {
             {
                "count",std::to_string(mempool.size())
            }
            , {
                "first_sequence",std::to_string(sequence-mempool.size()+1)
            }
            , {
                "last_sequence",std::to_string(sequence)
            }
            , {
                "root",json_escape(root)
            }
            , {
                "state_root",json_escape(sr)
            }
            , {
                "type",json_escape("l2_commitment")
            }
        }
        );
        std::string id=sha3_512(c);
        std::string out=c.substr(0,c.size()-1)+",\"tx_id\":"+json_escape(id)+"}";
        commitments.push_back(out);
        mempool.clear();
        return out;
    }
};
class SeenSet {
    size_t cap;
    std::set<std::string>s;
    std::vector<std::string>q;
    public:explicit SeenSet(size_t c):cap(c) {
    }
    bool contains(const std::string&x) {
        return s.count(x);
    }
    void add(const std::string&x) {
        if(s.count(x))return;
        s.insert(x);
        q.push_back(x);
        if(q.size()>cap) {
            s.erase(q.front());
            q.erase(q.begin());
        }
    }
};
static bool send_all(int fd,const char*p,size_t n) {
    while(n) {
        ssize_t r=send(fd,p,n,0);
        if(r<=0)return false;
        p+=r;
        n-=r;
    }
    return true;
}
static bool recv_all(int fd,char*p,size_t n) {
    while(n) {
        ssize_t r=recv(fd,p,n,0);
        if(r<=0)return false;
        p+=r;
        n-=r;
    }
    return true;
}
static bool send_frame(int fd,const std::string&s) {
    if(s.size()>MAX_FRAME_BYTES)return false;
    uint32_t n=htonl((uint32_t)s.size());
    return send_all(fd,(char*)&n,4)&&send_all(fd,s.data(),s.size());
}
static std::optional<std::string> recv_frame(int fd) {
    uint32_t n=0;
    if(!recv_all(fd,(char*)&n,4))return std::nullopt;
    n=ntohl(n);
    if(n==0||n>MAX_FRAME_BYTES)return std::nullopt;
    std::string s(n,'\0');
    if(!recv_all(fd,s.data(),n))return std::nullopt;
    return s;
}
static Transaction make_transfer(const Wallet&w,const std::string&to,i64 em,i64 nonce) {
    if(em<=0 || em>MAX_TX_AMOUNT/COIN) throw std::runtime_error("EM amount overflow/out of range");
    if(nonce<0) throw std::runtime_error("negative nonce");
    checked_amount(em*COIN);
    Transaction t;
    t.sender_pubkey=w.public_key_hex;
    t.recipient=to;
    t.amount=em*COIN;
    t.nonce=nonce;
    t.timestamp=now_s();
    t.signature=w.sign(t.signing_json());
    t.tx_id=hash_obj( {
         {
            "amount",std::to_string(t.amount)
        }
        , {
            "nonce",std::to_string(t.nonce)
        }
        , {
            "recipient",json_escape(t.recipient)
        }
        , {
            "sender_pubkey",json_escape(t.sender_pubkey)
        }
        , {
            "signature",json_escape(t.signature)
        }
        , {
            "timestamp",std::to_string(t.timestamp)
        }
    }
    );
    return t;
}
static MiningShare make_share(const std::string&m,const std::string&job,int d,u64 n) {
    MiningShare s;
    s.miner=m;
    s.job_id=job;
    s.difficulty=d;
    s.nonce=n;
    s.share_hash=s.calc_hash();
    s.share_id=s.calc_id();
    return s;
}
static void vector_test() {
    std::string miner(128,'a'),job(128,'b');
    MiningShare sh=make_share(miner,job,1,12345);
    Wallet pq;
    std::string pqmsg="EM_V17_PQ_VECTOR_MESSAGE";
    std::string pqsig=pq.sign(pqmsg);
    std::cout<<"PQ_PUB "<<pq.public_key_hex<<"\nPQ_ADDR "<<pq.address<<"\nPQ_MSG "<<pqmsg<<"\nPQ_SIG "<<pqsig<<"\nGEN_TX "<<hash_obj( {
         {
            "amount",std::to_string(BASE_REWARD)
        }
        ,  {
            "message",json_escape(GENESIS_MESSAGE)
        }
        ,  {
            "recipient",json_escape("Miner_Genesis")
        }
    }
    )<<"\n";
    std::cout<<"REWARD "<<hash_obj( {
         {
            "amount",std::to_string(INITIAL_BLOCK_REWARD)
        }
        ,  {
            "block_index","1"
        }
        ,  {
            "issuance",std::to_string(INITIAL_BLOCK_REWARD)
        }
        ,  {
            "recipient",json_escape(miner)
        }
        ,  {
            "type",json_escape("reward")
        }
    }
    )<<"\n";
    std::cout<<"SHARE_CHAL "<<sha3_512("ELECTRIC-MONEY-SHARE-"+NETWORK_ID+"-"+job+"-1")<<"\n";
    std::cout<<"SHARE_HASH "<<sh.share_hash<<"\n";
    std::cout<<"SHARE_ID "<<sh.share_id<<"\n";
    std::cout<<"SHARE_WORK "<<block_work(1)<<"\n";
    std::map<std::string,i64> vb {
         {
            std::string(128,'a'),987654321
        }
        , {
            std::string(128,'b'),123456789
        }
    };
    std::map<std::string,i64> vn {
         {
            std::string(128,'a'),7
        }
        , {
            std::string(128,'b'),2
        }
    };
    std::ostringstream bo,no;
    bo<<"{";
     {
        bool f=true;
        for(auto&[a,v]:vb) {
            if(!f)bo<<",";
            f=false;
            bo<<json_escape(a)<<":"<<v;
        }
    }
    bo<<"}";
    no<<"{";
     {
        bool f=true;
        for(auto&[a,v]:vn) {
            if(!f)no<<",";
            f=false;
            no<<json_escape(a)<<":"<<v;
        }
    }
    no<<"}";
    std::string sr=hash_obj( {
         {
            "balances",bo.str()
        }
        , {
            "nonces",no.str()
        }
    }
    );
    std::cout<<"STATE_ROOT "<<sr<<"\n";
    std::cout<<"COMMIT_ID "<<hash_obj( {
         {
            "count","2"
        }
        , {
            "first_sequence","1"
        }
        , {
            "last_sequence","2"
        }
        , {
            "root",json_escape(std::string(128,'c'))
        }
        , {
            "state_root",json_escape(sr)
        }
        , {
            "type",json_escape("l2_commitment")
        }
    }
    )<<"\n";
    std::filesystem::path d=std::filesystem::temp_directory_path()/"em_v17_vectors.json";
    std::error_code ec;
    std::filesystem::remove(d,ec);
    Blockchain bc(d.string());
    auto &g=bc.chain[0];
    std::cout<<"GEN_NONCE "<<g.nonce<<"\nGEN_HASH "<<g.block_hash<<"\nGEN_MERKLE "<<g.merkle_root<<"\n";
    std::filesystem::remove(d,ec);
}
static void make_fixture(const std::string&path) {
    std::error_code ec;
    std::filesystem::remove(path,ec);
    Blockchain bc(path);
    Wallet a,b;
    bc.mine_pending(a.address);
    auto tx=make_transfer(a,b.address,1,bc.next_nonce(a.address));
    if(!bc.add_transaction(tx))throw std::runtime_error("fixture tx admission failed");
    bc.mine_pending(b.address);
    if(!bc.validate_chain(bc.chain))throw std::runtime_error("fixture chain invalid");
    std::cout<<"FIXTURE_VALID height="<<bc.height()<<" work="<<bc.cumulative_work().convert_to<std::string>()<<" supply="<<bc.supply()<<"\n";
}
static void self_test() {
    std::cout<<"[SELF-TEST] creating ML-DSA-65 wallets...\n";
    Wallet a,b,m;
    Transaction p=make_transfer(a,a.address,1,0);
    if(p.signature.size()!=Wallet::SIG_HEX||!p.valid())throw std::runtime_error("PQ signature test failed");
    if(subsidy(1)!=INITIAL_BLOCK_REWARD||subsidy(HALVING_INTERVAL)!=INITIAL_BLOCK_REWARD/2)throw std::runtime_error("halving failed");
    std::filesystem::path d=std::filesystem::temp_directory_path()/"em_v17_test.json";
    std::error_code ec;
    std::filesystem::remove(d,ec);
    Blockchain bc(d.string());
    auto bl=bc.mine_pending(a.address);
    if(bl.index!=1||bc.balances[a.address]!=BASE_REWARD)throw std::runtime_error("mining failed");
    auto t=make_transfer(a,b.address,10,bc.next_nonce(a.address));
    if(!bc.add_transaction(t))throw std::runtime_error("tx admission failed");
    bc.mine_pending(m.address);
    i64 tt=(10*COIN*RECEIVER_TAX_BPS)/10000,bb=(10*COIN*TX_BURN_BPS)/10000;
    if(bc.balances[b.address]!=10*COIN-tt-bb||bc.total_burned<bb||bc.treasury_balance<tt)throw std::runtime_error("fee/burn failed");
    if(!bc.validate_chain(bc.chain))throw std::runtime_error("replay failed");
    if(bc.wallet_anchor["Miner_Genesis"]!=bc.chain[1].timestamp)throw std::runtime_error("genesis tax anchor initialization failed");
    // Regression test: an immediate first block must not charge the Genesis wallet.
    if(bc.treasury_balance>tt)throw std::runtime_error("unexpected genesis annual tax");

    // L2 regression: reject nonce overflow before mutating balances/state.
    Layer2Sequencer l2;
    std::string l2sender=sha3_512(std::string((char*)unhex(a.public_key_hex).data(),unhex(a.public_key_hex).size()));
    if(!l2.deposit(l2sender,2*COIN))throw std::runtime_error("L2 deposit failed");
    L2Transaction ltx;
    ltx.sender_pubkey=a.public_key_hex;
    ltx.recipient=b.address;
    ltx.amount=COIN;
    ltx.nonce=0;
    ltx.timestamp=now_s();
    ltx.signature=a.sign(ltx.signing());
    ltx.tx_id=hash_obj({
        {"amount",std::to_string(ltx.amount)},
        {"nonce",std::to_string(ltx.nonce)},
        {"recipient",json_escape(ltx.recipient)},
        {"sender_pubkey",json_escape(ltx.sender_pubkey)},
        {"signature",json_escape(ltx.signature)},
        {"timestamp",std::to_string(ltx.timestamp)}
    });
    if(!l2.add(ltx))throw std::runtime_error("L2 transfer failed");
    i64 sender_before=l2.balances[l2sender], recipient_before=l2.balances[b.address];
    L2Transaction overflow=ltx;
    overflow.nonce=std::numeric_limits<i64>::max();
    overflow.signature=a.sign(overflow.signing());
    overflow.tx_id=hash_obj({
        {"amount",std::to_string(overflow.amount)},
        {"nonce",std::to_string(overflow.nonce)},
        {"recipient",json_escape(overflow.recipient)},
        {"sender_pubkey",json_escape(overflow.sender_pubkey)},
        {"signature",json_escape(overflow.signature)},
        {"timestamp",std::to_string(overflow.timestamp)}
    });
    if(l2.add(overflow) || l2.balances[l2sender]!=sender_before || l2.balances[b.address]!=recipient_before)
        throw std::runtime_error("L2 nonce overflow mutated state");
    std::filesystem::remove(d,ec);
    std::cout<<"[SELF-TEST] all tests passed\n";
}
int main(int argc,char**argv) {
    try {
        bool test=false,vectors=false,mine=false,validate_db=false;
        std::string make_fixture_path;
        std::string db="electric_money_v17.json";
        for(int i=1;i<argc;i++) {
            std::string a=argv[i];
            if(a=="--self-test")test=true;
            else if(a=="--vectors")vectors=true;
            else if(a=="--validate-db")validate_db=true;
            else if(a=="--make-fixture"&&i+1<argc)make_fixture_path=argv[++i];
            else if(a=="--verify-pq"&&i+3<argc) {
                std::string pub=argv[++i],msg=argv[++i],sig=argv[++i];
                bool ok=Wallet::verify(pub,msg,sig);
                std::cout<<(ok?"VERIFY_OK":"VERIFY_FAIL")<<"\n";
                return ok?0:1;
            } else if(a=="--mine")mine=true;
            else if(a=="--db"&&i+1<argc)db=argv[++i];
        }
        if(vectors) {
            vector_test();
            return 0;
        }
        if(test) {
            self_test();
            return 0;
        }
        if(!make_fixture_path.empty()) {
            make_fixture(make_fixture_path);
            return 0;
        }
        Blockchain bc(db);
        if(validate_db) {
            std::cout<<"CHAIN_VALID height="<<bc.height()<<" work="<<bc.cumulative_work().convert_to<std::string>()<<" supply="<<bc.supply()<<"\n";
            return 0;
        }
        Wallet miner;
        std::cout<<"[NODE] miner address: "<<miner.address<<"\n";
        if(mine) {
            while(true) {
                Block b=bc.mine_pending(miner.address);
                std::cout<<"[MINER] block="<<b.index<<" difficulty="<<b.difficulty<<" work="<<bc.cumulative_work().convert_to<std::string>()<<"\n";
            }
        } else {
            std::cout<<"[NODE] height="<<bc.height()<<" supply="<<std::fixed<<std::setprecision(8)<<(double)bc.supply()/COIN<<" EM\n";
            for(;;)std::this_thread::sleep_for(std::chrono::minutes(1));
        }
    } catch(const std::exception&e) {
        std::cerr<<"fatal: "<<e.what()<<"\n";
        return 2;
    }
}
