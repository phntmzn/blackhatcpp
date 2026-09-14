// Compile: g++ -o form_fuzz form_fuzz.cpp -lcurl
// Run: ./form_fuzz <url> <param1> <param2>
// Requires: libcurl-dev

#include <iostream>
#include <string>
#include <vector>
#include <curl/curl.h>

class FormFuzzer {
private:
    std::vector<std::string> payloads;
    
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
        s->append((char*)contents, size * nmemb);
        return size * nmemb;
    }
    
public:
    FormFuzzer() {
        payloads = {"'", "\"", "<", ">", ";", "|", "&", "$", "`"};
    }
    
    void fuzz(const std::string& url, const std::vector<std::string>& params) {
        CURL* curl = curl_easy_init();
        if (!curl) return;
        
        for (const auto& p1 : payloads) {
            for (const auto& p2 : payloads) {
                std::string postData;
                for (size_t i = 0; i < params.size(); i++) {
                    if (i > 0) postData += "&";
                    postData += params[i] + "=" + (i == 0 ? p1 : p2);
                }
                
                std::string response;
                curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
                
                CURLcode res = curl_easy_perform(curl);
                if (res == CURLE_OK && response.find("error") != std::string::npos) {
                    std::cout << "[!] Potential injection: " << p1 << " / " << p2 << std::endl;
                }
            }
        }
        
        curl_easy_cleanup(curl);
    }
};

int main(int argc, char* argv[]) {
    if (argc < 4) { std::cerr << "Usage: " << argv[0] << " <url> <param1> <param2>\n"; return 1; }
    FormFuzzer fuzzer;
    fuzzer.fuzz(argv[1], {argv[2], argv[3]});
    return 0;
}