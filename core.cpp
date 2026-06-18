#include<bits/stdc++.h>
#include<openssl/evp.h>
#include<openssl/sha.h>
#include<openssl/rand.h>
using namespace std;

const string INTERNAL_KEY    = "VoteSys_AES_2024";
const string ADMIN_ID        = "admin";
const string ADMIN_PASS      = "system";
const string AGENT_ID        = "agent";
const string AGENT_PASS      = "agentpass";
const string BLOCKCHAIN_FILE = "election_data.enc";

class Blockchain;
class Wallet;
string sha256_hex(const string& data);
string get_secure_key();
string calculate_hash(int idx, const string& data, const string& prev, const string& ts, int nonce);
vector<unsigned char> aes_encrypt(const string& data, const string& key);
string aes_decrypt(const vector<unsigned char>& data, const string& key);
bool validate_voter_credentials(const string& id, const string& fp, const string& filepath);
void admin_panel(Blockchain& bc);
void polling_agent_panel(Blockchain& bc);
void user_registration(Blockchain& bc);
void user_login(Blockchain& bc);

string bytes_to_hex(const unsigned char* data, int len)
{
    ostringstream oss;
    for(int i=0; i<len; i++)
    {
        oss<<hex<<setw(2)<<setfill('0')<<(int)data[i];
    }
    return oss.str();
}

string sha256_hex(const string& data)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data.c_str(), data.size(), hash);
    return bytes_to_hex(hash, SHA256_DIGEST_LENGTH);
}

string get_secure_key()
{
    string k1 = "Vote";
    string k2 = "Sys_";
    string k3 = "AES_";
    string k4 = "2026";
    string k5 = "_Sec";
    string k6 = "ure_";
    string k7 = "Salt";
    string key = k1+k2+k3+k4+k5+k6+k7;
    for(int i=0;i<1000;i++)
    {
        key=sha256_hex(key);
    }
    return key;
}

string calculate_hash(int idx, const string& data, const string& prev, const string& ts, int nonce)
{
    string combined = to_string(idx)+data+prev+ts+to_string(nonce);
    return sha256_hex(combined);
}

vector<unsigned char> aes_encrypt(const string& data, const string& key)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    RAND_bytes(iv, 16);
    unsigned char keyBytes[32];
    SHA256((unsigned char*)key.c_str(), key.size(), keyBytes);
    vector<unsigned char> output(16+data.size()+16);
    for(int i=0; i<16; i++)
    {
        output[i]=iv[i];
    }
    int len=0;
    int total=0;
    if(EVP_EncryptInit_ex(ctx,EVP_aes_256_cbc(),NULL,keyBytes,iv)!=1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    if(EVP_EncryptUpdate(ctx,output.data()+16,&len,(unsigned char*)data.c_str(),(int)data.size())!=1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    total=len;
    if(EVP_EncryptFinal_ex(ctx,output.data()+16+len,&len)!=1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    total+=len;
    EVP_CIPHER_CTX_free(ctx);
    output.resize(16+total);
    return output;
}

string aes_decrypt(const vector<unsigned char>& data, const string& key)
{
    if(data.size()<16)
    {
        return "DECRYPT_ERROR";
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    for(int i=0; i<16; i++)
    {
        iv[i]=data[i];
    }
    unsigned char keyBytes[32];
    SHA256((unsigned char*)key.c_str(), key.size(), keyBytes);
    vector<unsigned char> output(data.size());
    int len=0;
    int total=0;
    if(EVP_DecryptInit_ex(ctx,EVP_aes_256_cbc(),NULL,keyBytes,iv)!=1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return "DECRYPT_ERROR";
    }
    if(EVP_DecryptUpdate(ctx,output.data(),&len,data.data()+16,(int)data.size()-16)!=1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return "DECRYPT_ERROR";
    }
    total=len;
    if(EVP_DecryptFinal_ex(ctx,output.data()+len,&len)!=1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return "DECRYPT_ERROR";
    }
    total+=len;
    EVP_CIPHER_CTX_free(ctx);
    return string(output.begin(), output.begin()+total);
}

string get_public_key(const string& secret)
{
    return "PUB_"+sha256_hex("VOTING_ROOT"+secret+"STABLE_ADDR");
}

string hash_voter_id(const string& v)
{
    return sha256_hex("VOTER_SALT_"+v);
}

string hash_fingerprint(const string& f)
{
    return sha256_hex("FINGERPRINT_SALT_"+f);
}

string generate_otp()
{
    unsigned char buf[4];
    RAND_bytes(buf, sizeof(buf));
    unsigned int val = ((unsigned int)buf[0]<<24)
                     |((unsigned int)buf[1]<<16)
                     |((unsigned int)buf[2]<<8)
                     |(unsigned int)buf[3];
    char otp[7];
    snprintf(otp, sizeof(otp), "%06d", val%1000000);
    return string(otp);
}

struct Node
{
    int index;
    vector<unsigned char> data;
    string previoushash;
    string hash;
    string timestamp;
    int nonce;
    Node* next;

    Node(int idx, vector<unsigned char> d, const string& prev)
        : index(idx), data(d), previoushash(prev), next(nullptr), nonce(0)
    {
        time_t now=time(0);
        char* dt=ctime(&now);
        timestamp=string(dt);
        if(!timestamp.empty()&&timestamp.back()=='\n')
        {
            timestamp.pop_back();
        }
        string ds(data.begin(),data.end());
        hash=calculate_hash(index,ds,previoushash,timestamp,nonce);
    }

    Node(int idx, vector<unsigned char> d, const string& prev, const string& ts, int nce)
        : index(idx), data(d), previoushash(prev), timestamp(ts), nonce(nce), next(nullptr)
    {
        string ds(data.begin(),data.end());
        hash=calculate_hash(index,ds,previoushash,timestamp,nonce);
    }
};

class Blockchain
{
private:
    Node* head;
    Node* tail;
    int size;
    bool loading;
    string voter_file_path;

    unordered_set<string>                    idx_allowed;
    unordered_map<string,string>             idx_pubaddr;
    unordered_map<string,string>             idx_fp;
    unordered_set<string>                    idx_voted;
    unordered_map<string,pair<string,time_t>>idx_otp;
    vector<string>                           idx_candidates;

public:
    Blockchain() : head(nullptr), tail(nullptr), size(0), loading(false), voter_file_path("data.txt") {}

    string get_voter_file_path()
    {
        return voter_file_path;
    }

    void set_voter_file_path(const string& path)
    {
        voter_file_path=path;
        string rec="CONFIG|VOTER_FILE|"+path;
        vector<unsigned char> d(rec.begin(),rec.end());
        insert_block(d);
    }

    void insert_block(vector<unsigned char> encData, const string& ts = "", int nce = -1)
    {
        string prevH=(tail)?tail->hash:"GENESIS_HASH";
        Node* newNode=nullptr;
        if(!ts.empty()&&nce!=-1)
        {
            newNode=new Node(size,encData,prevH,ts,nce);
        }
        else
        {
            newNode=new Node(size,encData,prevH);
            if(!loading)
            {
                string ds(encData.begin(),encData.end());
                while(newNode->hash[0]!='0')
                {
                    newNode->nonce++;
                    newNode->hash=calculate_hash(newNode->index,ds,newNode->previoushash,newNode->timestamp,newNode->nonce);
                }
            }
        }

        if(!head)
        {
            head=tail=newNode;
        }
        else
        {
            tail->next=newNode;
            tail=newNode;
        }
        size++;

        string rec(encData.begin(),encData.end());
        if(rec.find("ALLOWED_VOTER|")==0)
        {
            idx_allowed.insert(rec.substr(14));
        }
        else if(rec.find("VOTER_ACCOUNT|")==0)
        {
            size_t p1=rec.find("|");
            size_t p2=rec.find("|",p1+1);
            size_t p3=rec.find("|",p2+1);
            string vh =rec.substr(p1+1,p2-p1-1);
            string pub=(p3!=string::npos)?rec.substr(p2+1,p3-p2-1):rec.substr(p2+1);
            string fp =(p3!=string::npos)?rec.substr(p3+1):"";
            idx_pubaddr[vh]=pub;
            idx_fp[vh]=fp;
        }
        else if(rec.find("HAS_VOTED|")==0)
        {
            idx_voted.insert(rec.substr(10));
        }
        else if(rec.find("OTP|")==0)
        {
            size_t p1=rec.find("|");
            size_t p2=rec.find("|",p1+1);
            size_t p3=rec.find("|",p2+1);
            string pk =rec.substr(p1+1,p2-p1-1);
            string ov =rec.substr(p2+1,p3-p2-1);
            time_t ts =(time_t)stoll(rec.substr(p3+1));
            idx_otp[pk]={ov,ts};
        }
        else if(rec.find("OPTION|")==0)
        {
            string name=rec.substr(7);
            if(find(idx_candidates.begin(),idx_candidates.end(),name)==idx_candidates.end())
            {
                idx_candidates.push_back(name);
            }
        }

        if(!loading)
        {
            // save with embedded metadata: BLK|index|prevHash|timestamp|nonce|data
            save_block_to_disk(encData, newNode->index, prevH, newNode->timestamp, newNode->nonce);
        }
    }

    void save_block_to_disk(const vector<unsigned char>& blockData, int blk_idx, const string& blk_prev, const string& blk_ts, int blk_nonce)
    {
        string data_str(blockData.begin(),blockData.end());
        // embed index + prevHash + timestamp + nonce inside payload so tampering is detectable
        string payload = "BLK|"+to_string(blk_idx)+"|"+blk_prev+"|"+blk_ts+"|"+to_string(blk_nonce)+"|"+data_str;
        vector<unsigned char> enc=aes_encrypt(payload,get_secure_key());
        ofstream file(BLOCKCHAIN_FILE,ios::app|ios::binary);
        int s=(int)enc.size();
        file.write((char*)&s,sizeof(s));
        file.write((char*)enc.data(),s);
        file.flush();
        file.close();
    }

    void load_blockchain()
    {
        ifstream file(BLOCKCHAIN_FILE,ios::binary);
        if(!file.is_open())
        {
            cout<<">>> No existing blockchain file. Starting fresh."<<endl;
            return;
        }
        clear_memory();
        loading=true;
        int loaded=0;
        bool tampered=false;

        while(true)
        {
            int s=0;
            if(!file.read((char*)&s,sizeof(s)))
            {
                break;
            }
            if(s<=0||s>10000000)
            {
                cerr<<">>> [WARNING] Corrupt block at index "<<loaded<<endl;
                break;
            }
            vector<unsigned char> enc(s);
            if(!file.read((char*)enc.data(),s))
            {
                break;
            }
            string dec=aes_decrypt(enc,get_secure_key());
            if(dec=="DECRYPT_ERROR")
            {
                cout<<">>> [TAMPER] Block "<<loaded<<" cannot be decrypted!"<<endl;
                tampered=true;
                continue;
            }

            string actual_data=dec;
            string stored_ts="";
            int    stored_nonce=-1;

            if(dec.find("BLK|")==0)
            {
                // parse embedded metadata: BLK|index|prevHash|timestamp|nonce|data
                size_t p1=dec.find("|");
                size_t p2=dec.find("|",p1+1);
                size_t p3=dec.find("|",p2+1);
                size_t p4=dec.find("|",p3+1);
                size_t p5=dec.find("|",p4+1);
                if(p5!=string::npos)
                {
                    int    stored_idx  =stoi(dec.substr(p1+1,p2-p1-1));
                    string stored_prev =dec.substr(p2+1,p3-p2-1);
                    stored_ts          =dec.substr(p3+1,p4-p3-1);
                    stored_nonce       =stoi(dec.substr(p4+1,p5-p4-1));
                    actual_data        =dec.substr(p5+1);

                    // check 1: sequential index — detects deleted blocks
                    if(stored_idx!=loaded)
                    {
                        cout<<">>> [TAMPER] Index gap! Expected "<<loaded<<" but block says "<<stored_idx<<endl;
                        tampered=true;
                    }

                    // check 2: stored prevHash must match last block's hash — detects injection + forgery
                    string expected_prev=(tail)?tail->hash:"GENESIS_HASH";
                    if(stored_prev!=expected_prev)
                    {
                        cout<<">>> [TAMPER] Hash mismatch at block "<<loaded<<"! Chain was modified."<<endl;
                        tampered=true;
                    }
                }
                else
                {
                    cout<<">>> [TAMPER] Block "<<loaded<<" has invalid integrity header format!"<<endl;
                    tampered=true;
                }
            }
            else
            {
                // old format block (no BLK| prefix) — treat as injected
                cout<<">>> [TAMPER] Block "<<loaded<<" has no integrity header! Possibly injected."<<endl;
                tampered=true;
            }

            if(actual_data.find("CONFIG|VOTER_FILE|")==0)
            {
                voter_file_path=actual_data.substr(18);
            }
            vector<unsigned char> blockData(actual_data.begin(),actual_data.end());
            insert_block(blockData,stored_ts,stored_nonce);
            loaded++;
        }

        loading=false;
        file.close();
        if(loaded>0)
        {
            cout<<">>> [OK] "<<loaded<<" blocks loaded from "<<BLOCKCHAIN_FILE<<endl;
            if(tampered)
            {
                cout<<">>> [!!!] BLOCKCHAIN INTEGRITY FAILED! Data has been tampered!"<<endl;
            }
            else
            {
                cout<<">>> [OK] All blocks passed integrity check."<<endl;
            }
            print_summary();
        }
    }

    bool validate_chain()
    {
        // re-read from disk and verify every block's embedded metadata
        ifstream file(BLOCKCHAIN_FILE,ios::binary);
        if(!file.is_open())
        {
            cout<<">>> [ERROR] Cannot open blockchain file for validation."<<endl;
            return false;
        }

        bool ok=true;
        int  idx=0;
        string last_hash="GENESIS_HASH";

        cout<<">>> Validating chain from disk..."<<endl;
        while(true)
        {
            int s=0;
            if(!file.read((char*)&s,sizeof(s)))
            {
                break;
            }
            if(s<=0||s>10000000)
            {
                break;
            }
            vector<unsigned char> enc(s);
            if(!file.read((char*)enc.data(),s))
            {
                break;
            }
            string dec=aes_decrypt(enc,get_secure_key());
            if(dec=="DECRYPT_ERROR")
            {
                cout<<">>> [TAMPER] Block "<<idx<<" cannot be decrypted!"<<endl;
                ok=false;
                idx++;
                continue;
            }

            if(dec.find("BLK|")==0)
            {
                size_t p1=dec.find("|");
                size_t p2=dec.find("|",p1+1);
                size_t p3=dec.find("|",p2+1);
                size_t p4=dec.find("|",p3+1);
                size_t p5=dec.find("|",p4+1);
                if(p5!=string::npos)
                {
                    int    stored_idx  =stoi(dec.substr(p1+1,p2-p1-1));
                    string stored_prev =dec.substr(p2+1,p3-p2-1);
                    string stored_ts   =dec.substr(p3+1,p4-p3-1);
                    int    stored_nonce=stoi(dec.substr(p4+1,p5-p4-1));
                    string actual_data =dec.substr(p5+1);

                    // verify sequential index
                    if(stored_idx!=idx)
                    {
                        cout<<">>> [TAMPER] Block deleted or injected near index "<<idx<<"!"<<endl;
                        ok=false;
                    }

                    // verify prevHash link
                    if(stored_prev!=last_hash)
                    {
                        cout<<">>> [TAMPER] Block "<<idx<<" prevHash mismatch! Data forged or block removed."<<endl;
                        ok=false;
                    }

                    // recompute hash to update last_hash for next iteration
                    last_hash=calculate_hash(idx,actual_data,stored_prev,stored_ts,stored_nonce);
                }
                else
                {
                    cout<<">>> [TAMPER] Block "<<idx<<" has invalid integrity header format!"<<endl;
                    ok=false;
                }
            }
            else
            {
                cout<<">>> [TAMPER] Block "<<idx<<" missing integrity header — possibly injected!"<<endl;
                ok=false;
            }
            idx++;
        }
        file.close();

        if(ok)
        {
            cout<<">>> [OK] All "<<idx<<" blocks verified. Chain is CLEAN."<<endl;
        }
        else
        {
            cout<<">>> [!!!] CHAIN COMPROMISED! Evidence of piracy/tampering found."<<endl;
        }
        return ok;
    }

    void print_summary()
    {
        int voters=0;
        int accounts=0;
        int candidates=0;
        int votes=0;
        ifstream vf(voter_file_path);
        if(vf.is_open())
        {
            string id,fp;
            while(vf>>id>>fp)
            {
                voters++;
            }
            vf.close();
        }
        Node* curr=head;
        while(curr)
        {
            string dec(curr->data.begin(),curr->data.end());
            if(dec.find("VOTER_ACCOUNT|")==0)
            {
                accounts++;
            }
            else if(dec.find("OPTION|")==0)
            {
                candidates++;
            }
            else if(dec.find("ANONYMOUS_VOTE|")==0)
            {
                votes++;
            }
            curr=curr->next;
        }
        cout<<">>> Total Blocks       : "<<size<<endl;
        cout<<">>> Eligible Voters    : "<<voters<<" (from: "<<voter_file_path<<")"<<endl;
        cout<<">>> Registered Accounts: "<<accounts<<endl;
        cout<<">>> Candidates         : "<<candidates<<endl;
        cout<<">>> Votes Cast         : "<<votes<<endl;
    }

    Node* get_head()
    {
        return head;
    }

    bool is_voter_allowed(const string& voterHash)
    {
        return idx_allowed.count(voterHash)>0;
    }

    bool is_voter_registered(const string& voterHash)
    {
        return idx_pubaddr.count(voterHash)>0;
    }

    bool has_voted(const string& pubKey)
    {
        return idx_voted.count(pubKey)>0;
    }

    vector<string> get_options()
    {
        return idx_candidates;
    }

    string get_public_address(const string& voterHash)
    {
        auto it=idx_pubaddr.find(voterHash);
        if(it!=idx_pubaddr.end())
        {
            return it->second;
        }
        return "";
    }

    string get_fingerprint_hash(const string& voterHash)
    {
        auto it=idx_fp.find(voterHash);
        if(it!=idx_fp.end())
        {
            return it->second;
        }
        return "";
    }

    bool get_latest_otp(const string& pubKey, string& otp_out, time_t& time_out)
    {
        auto it=idx_otp.find(pubKey);
        if(it==idx_otp.end())
        {
            return false;
        }
        otp_out =it->second.first;
        time_out=it->second.second;
        return true;
    }

    void factory_reset()
    {
        clear_memory();
        ofstream f(BLOCKCHAIN_FILE,ios::trunc|ios::binary);
        f.close();
        cout<<">>> [RESET] All data wiped."<<endl;
    }

    void reset_votes()
    {
        vector<vector<unsigned char>> keep;
        Node* curr=head;
        while(curr)
        {
            string dec(curr->data.begin(),curr->data.end());
            bool is_vote=dec.find("ANONYMOUS_VOTE|")==0
                        ||dec.find("HAS_VOTED|")==0
                        ||dec.find("OTP|")==0;
            if(!is_vote)
            {
                keep.push_back(curr->data);
            }
            curr=curr->next;
        }
        rebuild_chain(keep);
        cout<<">>> [RESET] Votes and OTPs cleared."<<endl;
    }

    void reset_candidates_and_votes()
    {
        vector<vector<unsigned char>> keep;
        Node* curr=head;
        while(curr)
        {
            string dec(curr->data.begin(),curr->data.end());
            bool remove=dec.find("ANONYMOUS_VOTE|")==0
                       ||dec.find("HAS_VOTED|")==0
                       ||dec.find("OTP|")==0
                       ||dec.find("OPTION|")==0
                       ||dec.find("ALLOWED_VOTER|")==0;
            if(!remove)
            {
                keep.push_back(curr->data);
            }
            curr=curr->next;
        }
        rebuild_chain(keep);
        cout<<">>> [RESET] Candidates, votes, OTPs cleared."<<endl;
    }

    void clear_voter_data()
    {
        vector<vector<unsigned char>> keep;
        Node* curr=head;
        while(curr)
        {
            string dec(curr->data.begin(),curr->data.end());
            bool is_voter=dec.find("ALLOWED_VOTER|")==0
                         ||dec.find("VOTER_ACCOUNT|")==0
                         ||dec.find("HAS_VOTED|")==0
                         ||dec.find("OTP|")==0
                         ||dec.find("ANONYMOUS_VOTE|")==0;
            if(!is_voter)
            {
                keep.push_back(curr->data);
            }
            curr=curr->next;
        }
        rebuild_chain(keep);
        cout<<">>> [INFO] Voter data cleared. Ready for new file."<<endl;
    }

private:
    void clear_memory()
    {
        Node* curr=head;
        while(curr)
        {
            Node* tmp=curr;
            curr=curr->next;
            delete tmp;
        }
        head=tail=nullptr;
        size=0;
        idx_allowed.clear();
        idx_pubaddr.clear();
        idx_fp.clear();
        idx_voted.clear();
        idx_otp.clear();
        idx_candidates.clear();
    }

    void rebuild_chain(const vector<vector<unsigned char>>& keep)
    {
        clear_memory();
        ofstream f(BLOCKCHAIN_FILE,ios::trunc|ios::binary);
        f.close();
        for(const auto& d:keep)
        {
            insert_block(d);
        }
    }
};

class Wallet
{
public:
    string secret;
    string public_address;

    Wallet(const string& sec) : secret(sec)
    {
        public_address=get_public_key(secret);
    }
};

bool validate_voter_credentials(const string& id, const string& fp, const string& filepath)
{
    ifstream file(filepath);
    if(!file.is_open())
    {
        cout<<">>> [ERROR] Cannot open voter file: "<<filepath<<endl;
        return false;
    }
    string line_id;
    string line_fp;
    while(file>>line_id>>line_fp)
    {
        if(line_id==id&&line_fp==fp)
        {
            file.close();
            return true;
        }
    }
    file.close();
    return false;
}

void admin_panel(Blockchain& bc)
{
    string user;
    string pass;
    cout<<"\n--- Admin Login ---"<<endl;
    cout<<"ID       : "; cin>>user;
    cout<<"Password : "; cin>>pass;

    if(user!=ADMIN_ID||pass!=ADMIN_PASS)
    {
        cout<<">>> [DENIED] Invalid admin credentials!"<<endl;
        return;
    }

    while(true)
    {
        cout<<"\n========== ADMIN DASHBOARD =========="<<endl;
        cout<<"1. Load Voter File"<<endl;
        cout<<"2. Add Candidate"<<endl;
        cout<<"3. View Live Results"<<endl;
        cout<<"4. Verify Blockchain Integrity"<<endl;
        cout<<"5. Advanced Reset"<<endl;
        cout<<"6. Logout"<<endl;
        cout<<"Choice: ";

        int choice;
        if(!(cin>>choice))
        {
            cin.clear();
            cin.ignore(10000,'\n');
            continue;
        }

        if(choice==1)
        {
            string path;
            cout<<"Enter voter file path: ";
            cin.ignore(10000,'\n');
            getline(cin,path);
            while(!path.empty()&&(path.front()=='"'||path.front()==' '))
            {
                path.erase(path.begin());
            }
            while(!path.empty()&&(path.back()=='"'||path.back()==' '))
            {
                path.pop_back();
            }
            ifstream f(path);
            if(!f.is_open())
            {
                cout<<">>> [ERROR] Cannot open: '"<<path<<"'"<<endl;
            }
            else
            {
                bc.clear_voter_data();
                bc.set_voter_file_path(path);
                string vid;
                string vfp;
                int added=0;
                while(f>>vid>>vfp)
                {
                    string h=hash_voter_id(vid);
                    if(!bc.is_voter_allowed(h))
                    {
                        string rec="ALLOWED_VOTER|"+h;
                        vector<unsigned char> d(rec.begin(),rec.end());
                        bc.insert_block(d);
                        added++;
                    }
                }
                f.close();
                cout<<">>> [OK] "<<added<<" voter entries loaded from '"<<path<<"'."<<endl;
            }
        }
        else if(choice==2)
        {
            string name;
            cout<<"Candidate Name: ";
            cin.ignore(10000,'\n');
            getline(cin,name);
            string rec="OPTION|"+name;
            vector<unsigned char> d(rec.begin(),rec.end());
            bc.insert_block(d);
            cout<<">>> [OK] Candidate '"<<name<<"' added."<<endl;
        }
        else if(choice==3)
        {
            bc.load_blockchain();
            vector<string> opts=bc.get_options();
            if(opts.empty())
            {
                cout<<">>> No candidates added yet."<<endl;
            }
            else
            {
                cout<<"\n--- Live Results ---"<<endl;
                string winner="";
                int top=-1;
                for(const string& opt:opts)
                {
                    int count=0;
                    string opt_hash=sha256_hex("VOTE_SALT_"+opt);
                    Node* curr=bc.get_head();
                    while(curr)
                    {
                        string dec(curr->data.begin(),curr->data.end());
                        if(dec.find("ANONYMOUS_VOTE|")==0&&dec.substr(15)==opt_hash)
                        {
                            count++;
                        }
                        curr=curr->next;
                    }
                    cout<<"  "<<opt<<" : "<<count<<" votes"<<endl;
                    if(count>top)
                    {
                        top=count;
                        winner=opt;
                    }
                }
                if(top>=0)
                {
                    cout<<"\n>>> Leader: "<<winner<<" ("<<top<<" votes)"<<endl;
                }
            }
        }
        else if(choice==4)
        {
            bc.load_blockchain();
            bc.validate_chain();
        }
        else if(choice==5)
        {
            cout<<"\n!!! DANGER ZONE !!!"<<endl;
            cout<<"1. Reset Votes Only"<<endl;
            cout<<"2. Reset Candidates + Votes"<<endl;
            cout<<"3. Factory Reset (wipe EVERYTHING)"<<endl;
            cout<<"4. Cancel"<<endl;
            cout<<"Choice: ";
            int sub;
            if(!(cin>>sub))
            {
                cin.clear();
                cin.ignore(10000,'\n');
                continue;
            }
            char confirm;
            if(sub==1)
            {
                cout<<"Reset all votes? (y/n): ";
                cin>>confirm;
                if(confirm=='y'||confirm=='Y')
                {
                    bc.reset_votes();
                }
            }
            else if(sub==2)
            {
                cout<<"Reset candidates + votes? (y/n): ";
                cin>>confirm;
                if(confirm=='y'||confirm=='Y')
                {
                    bc.reset_candidates_and_votes();
                }
            }
            else if(sub==3)
            {
                cout<<"Type CONFIRM to wipe everything: ";
                string word;
                cin>>word;
                if(word=="CONFIRM")
                {
                    bc.factory_reset();
                }
                else
                {
                    cout<<">>> Cancelled."<<endl;
                }
            }
        }
        else if(choice==6)
        {
            break;
        }
    }
}

void polling_agent_panel(Blockchain& bc)
{
    bc.load_blockchain();
    string user;
    string pass;
    cout<<"\n--- Polling Agent Login ---"<<endl;
    cout<<"ID       : "; cin>>user;
    cout<<"Password : "; cin>>pass;

    if(user!=AGENT_ID||pass!=AGENT_PASS)
    {
        cout<<">>> [DENIED] Invalid agent credentials!"<<endl;
        return;
    }

    while(true)
    {
        cout<<"\n========== POLLING AGENT DASHBOARD =========="<<endl;
        cout<<"1. Issue OTP for Voter"<<endl;
        cout<<"2. Logout"<<endl;
        cout<<"Choice: ";
        int choice;
        if(!(cin>>choice))
        {
            cin.clear();
            cin.ignore(10000,'\n');
            continue;
        }

        if(choice==1)
        {
            bc.load_blockchain();
            string voterNum;
            cout<<"Voter Number: ";
            cin>>voterNum;

            string h=hash_voter_id(voterNum);
            if(!bc.is_voter_registered(h))
            {
                cout<<">>> [ERROR] Voter has not registered yet!"<<endl;
                continue;
            }

            string fp;
            cout<<"Voter Fingerprint: ";
            cin>>fp;
            string fp_hash   =hash_fingerprint(fp);
            string stored_fp =bc.get_fingerprint_hash(h);

            if(stored_fp.empty()||fp_hash!=stored_fp)
            {
                cout<<">>> [DENIED] Fingerprint mismatch! OTP not issued."<<endl;
                continue;
            }
            cout<<">>> [OK] Fingerprint verified."<<endl;

            string pubAddr=bc.get_public_address(h);
            if(pubAddr.empty())
            {
                cout<<">>> [ERROR] Voter address not found."<<endl;
                continue;
            }

            string existing_otp;
            time_t existing_time;
            if(bc.get_latest_otp(pubAddr,existing_otp,existing_time))
            {
                if(time(0)-existing_time<=300)
                {
                    cout<<">>> [DENIED] Active OTP already exists. Wait for it to expire."<<endl;
                    continue;
                }
                cout<<">>> [INFO] Previous OTP expired. Generating new one..."<<endl;
            }

            string otp=generate_otp();
            time_t now=time(0);
            string rec="OTP|"+pubAddr+"|"+otp+"|"+to_string(now);
            vector<unsigned char> d(rec.begin(),rec.end());
            bc.insert_block(d);

            cout<<">>> [SUCCESS] OTP issued: "<<otp<<endl;
            cout<<">>> Valid for 5 minutes."<<endl;
        }
        else if(choice==2)
        {
            break;
        }
    }
}

void user_registration(Blockchain& bc)
{
    bc.load_blockchain();
    cout<<"\n--- Voter Registration ---"<<endl;
    string voterNum;
    string fingerprint;
    cout<<"Voter Number         : "; cin>>voterNum;
    cout<<"Fingerprint (4-digit): "; cin>>fingerprint;

    if(!validate_voter_credentials(voterNum,fingerprint,bc.get_voter_file_path()))
    {
        cout<<">>> [ERROR] ID / Fingerprint not in records!"<<endl;
        return;
    }

    string h=hash_voter_id(voterNum);
    if(!bc.is_voter_allowed(h))
    {
        cout<<">>> [ERROR] Voter not in allowed list. Admin must load voter file first!"<<endl;
        return;
    }
    if(bc.is_voter_registered(h))
    {
        cout<<">>> [ERROR] Account already exists for this voter!"<<endl;
        return;
    }

    string enc_fp =hash_fingerprint(fingerprint);
    string secret ="SEC_"+sha256_hex("USER_LOGIN_"+voterNum+to_string(time(0)));
    Wallet* w     =new Wallet(secret);

    string rec="VOTER_ACCOUNT|"+h+"|"+w->public_address+"|"+enc_fp;
    vector<unsigned char> d(rec.begin(),rec.end());
    bc.insert_block(d);

    cout<<"\n>>> [SUCCESS] Voter Account Created!"<<endl;
    cout<<"=============================================="<<endl;
    cout<<">>> YOUR SECRET KEY : "<<secret<<endl;
    cout<<"=============================================="<<endl;
    cout<<">>> IMPORTANT: This key is NEVER saved to the blockchain!"<<endl;

    char save;
    cout<<"\nSave credentials to file? (y/n): ";
    cin>>save;
    if(save=='y'||save=='Y')
    {
        string fname;
        cout<<"Filename (e.g. my_key.txt): ";
        cin>>fname;
        ofstream out(fname);
        if(out.is_open())
        {
            out<<"======================================\n";
            out<<"        VOTER CREDENTIALS             \n";
            out<<"======================================\n";
            out<<"Voter Number : "<<voterNum<<"\n";
            out<<"Secret Key   : "<<secret<<"\n";
            out<<"Fingerprint  : "<<fingerprint<<"\n";
            out<<"--------------------------------------\n";
            out<<"WARNING: Do NOT share this file!\n";
            out.close();
            cout<<">>> [OK] Saved to '"<<fname<<"'."<<endl;
        }
        else
        {
            cout<<">>> [ERROR] Could not write to file."<<endl;
        }
    }
    delete w;
}

void user_login(Blockchain& bc)
{
    bc.load_blockchain();
    string secret;
    string fingerprint;
    cout<<"\n--- Voter Login ---"<<endl;
    cout<<"Secret Key  : "; cin>>secret;
    cout<<"Fingerprint : "; cin>>fingerprint;

    string pub   =get_public_key(secret);
    string enc_fp=hash_fingerprint(fingerprint);

    bool exists=false;
    Node* curr=bc.get_head();
    while(curr)
    {
        string dec(curr->data.begin(),curr->data.end());
        if(dec.find("VOTER_ACCOUNT|")==0)
        {
            size_t p1=dec.find("|");
            size_t p2=dec.find("|",p1+1);
            size_t p3=dec.find("|",p2+1);
            string saved_pub=(p3!=string::npos)?dec.substr(p2+1,p3-p2-1):dec.substr(p2+1);
            string saved_fp =(p3!=string::npos)?dec.substr(p3+1):"";
            if(saved_pub==pub&&(saved_fp.empty()||saved_fp==enc_fp))
            {
                exists=true;
                break;
            }
        }
        curr=curr->next;
    }

    if(!exists)
    {
        cout<<">>> [ERROR] Invalid credentials or account not found!"<<endl;
        return;
    }
    cout<<">>> [OK] Login successful!"<<endl;

    while(true)
    {
        cout<<"\n---------- VOTER DASHBOARD ----------"<<endl;
        cout<<"1. Cast Vote"<<endl;
        cout<<"2. View Candidates"<<endl;
        cout<<"3. Save Credentials to File"<<endl;
        cout<<"4. Logout"<<endl;
        cout<<"Choice: ";
        int choice;
        if(!(cin>>choice))
        {
            cin.clear();
            cin.ignore(10000,'\n');
            continue;
        }

        if(choice==1)
        {
            if(bc.has_voted(pub))
            {
                cout<<">>> [DENIED] You have already voted!"<<endl;
                continue;
            }
            bc.load_blockchain();

            string entered_otp;
            cout<<"Enter 6-digit OTP from Polling Agent: ";
            cin>>entered_otp;

            string valid_otp;
            time_t otp_time;
            if(!bc.get_latest_otp(pub,valid_otp,otp_time))
            {
                cout<<">>> [DENIED] No OTP found. Visit a Polling Agent."<<endl;
                continue;
            }
            if(entered_otp!=valid_otp)
            {
                cout<<">>> [DENIED] Incorrect OTP!"<<endl;
                continue;
            }
            if(time(0)-otp_time>300)
            {
                cout<<">>> [DENIED] OTP expired. Get a new one from the Polling Agent."<<endl;
                continue;
            }

            vector<string> opts=bc.get_options();
            if(opts.empty())
            {
                cout<<">>> No candidates available yet."<<endl;
                continue;
            }

            cout<<"\nSelect Candidate:"<<endl;
            for(int i=0; i<(int)opts.size(); i++)
            {
                cout<<"  "<<i+1<<". "<<opts[i]<<endl;
            }

            int v;
            if(!(cin>>v)||v<1||v>(int)opts.size())
            {
                cout<<">>> Invalid selection."<<endl;
                continue;
            }

            string voted_rec="HAS_VOTED|"+pub;
            vector<unsigned char> id_data(voted_rec.begin(),voted_rec.end());
            bc.insert_block(id_data);

            string opt_hash =sha256_hex("VOTE_SALT_"+opts[v-1]);
            string vote_rec ="ANONYMOUS_VOTE|"+opt_hash;
            vector<unsigned char> vote_data(vote_rec.begin(),vote_rec.end());
            bc.insert_block(vote_data);

            cout<<">>> [SUCCESS] Vote cast anonymously!"<<endl;
        }
        else if(choice==2)
        {
            vector<string> opts=bc.get_options();
            cout<<"\n--- Candidates ---"<<endl;
            for(const string& s:opts)
            {
                cout<<"  - "<<s<<endl;
            }
            if(opts.empty())
            {
                cout<<"  (none added yet)"<<endl;
            }
        }
        else if(choice==3)
        {
            string fname;
            cout<<"Filename (e.g. backup.txt): ";
            cin>>fname;
            ofstream out(fname);
            if(out.is_open())
            {
                out<<"======================================\n";
                out<<"        VOTER CREDENTIALS             \n";
                out<<"======================================\n";
                out<<"Secret Key  : "<<secret<<"\n";
                out<<"Fingerprint : "<<fingerprint<<"\n";
                out<<"Public Addr : "<<pub<<"\n";
                out<<"--------------------------------------\n";
                out<<"WARNING: Do NOT share this file!\n";
                out.close();
                cout<<">>> [OK] Saved to '"<<fname<<"'."<<endl;
            }
            else
            {
                cout<<">>> [ERROR] Could not write to file."<<endl;
            }
        }
        else if(choice==4)
        {
            break;
        }
    }
}

int main()
{
    Blockchain bc;
    bc.load_blockchain();

    while(true)
    {
        cout<<"\n=============================================="<<endl;
        cout<<"     BLOCKCHAIN VOTING SYSTEM v2.0"<<endl;
        cout<<"     AES-128 Encrypted + SHA-256 Hashed"<<endl;
        cout<<"=============================================="<<endl;
        cout<<"1. Admin Login"<<endl;
        cout<<"2. Polling Agent Login"<<endl;
        cout<<"3. Voter Registration"<<endl;
        cout<<"4. Voter Login (Cast Vote)"<<endl;
        cout<<"5. Exit"<<endl;
        cout<<"Choice: ";

        int choice;
        if(!(cin>>choice))
        {
            cin.clear();
            cin.ignore(10000,'\n');
            cout<<">>> Invalid input. Enter 1-5."<<endl;
            continue;
        }

        if(choice==1)      { admin_panel(bc); }
        else if(choice==2) { polling_agent_panel(bc); }
        else if(choice==3) { user_registration(bc); }
        else if(choice==4) { user_login(bc); }
        else if(choice==5) { cout<<">>> Goodbye."<<endl; break; }
        else               { cout<<">>> Invalid choice."<<endl; }
    }

    return 0;
}