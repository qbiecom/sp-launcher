#include "custom_pak_signing.hpp"
#include "signing_fixture.hpp"
#include <array>
#include <cstdio>
#include <vector>
#include <algorithm>
#include <iterator>

int main() {
    std::array<wchar_t,MAX_PATH> directory{},path{};
    if (!GetTempPathW(static_cast<DWORD>(directory.size()),directory.data()) ||
        !GetTempFileNameW(directory.data(),L"spf",0,path.data())) return 1;
    HANDLE file=CreateFileW(path.data(),GENERIC_READ|GENERIC_WRITE,0,nullptr,
                            CREATE_ALWAYS,FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE,nullptr);
    if (file==INVALID_HANDLE_VALUE) { DeleteFileW(path.data()); return 2; }
    DWORD written=0;
    bool okay=WriteFile(file,kSigningFixture,sizeof(kSigningFixture),&written,nullptr) && written==sizeof(kSigningFixture);
    auto verify=[&](const unsigned char* signature,std::size_t size,const unsigned char* chunks,std::size_t chunksSize) {
        return clientfixes_signing::VerifyFile(file,signature,size,chunks,chunksSize);
    };
    okay=okay && verify(kSigningFixtureSignature,sizeof(kSigningFixtureSignature),kSigningFixtureChunks,sizeof(kSigningFixtureChunks));
    std::vector<unsigned char> signature(std::begin(kSigningFixtureSignature),std::end(kSigningFixtureSignature));
    signature[7]^=1;
    okay=okay && !verify(signature.data(),signature.size(),kSigningFixtureChunks,sizeof(kSigningFixtureChunks));
    okay=okay && !verify(kSigningFixtureSignature,511,kSigningFixtureChunks,sizeof(kSigningFixtureChunks));
    std::array<unsigned char,4> chunks{};
    std::copy(std::begin(kSigningFixtureChunks),std::end(kSigningFixtureChunks),chunks.begin());
    chunks[0]^=1;
    okay=okay && !verify(kSigningFixtureSignature,sizeof(kSigningFixtureSignature),chunks.data(),chunks.size());
    okay=okay && !verify(kSigningFixtureSignature,sizeof(kSigningFixtureSignature),chunks.data(),0);
    LARGE_INTEGER zero{};
    okay=okay && SetFilePointerEx(file,zero,nullptr,FILE_BEGIN);
    unsigned char changed=0;
    okay=okay && WriteFile(file,&changed,1,&written,nullptr) && written==1;
    okay=okay && !verify(kSigningFixtureSignature,sizeof(kSigningFixtureSignature),kSigningFixtureChunks,sizeof(kSigningFixtureChunks));
    CloseHandle(file);
    std::puts(okay ? "Signing verification passed: valid fixture accepted; modified PAK, CRC table, signature and invalid lengths rejected."
                   : "Signing verification FAILED.");
    return okay ? 0 : 3;
}