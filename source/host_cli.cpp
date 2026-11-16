// host_cli.cpp — cp268 kanıt: protect() motorunu HOST'ta koşar (wine'siz)
// kullanım: host_cli <girdi> <cikti> [--all] [--vmn N] [--vmadv] [--sdkonly] ...
#include "engine.hpp"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

int protect(const std::string& in, const std::string& out, const Options& opt,
            std::vector<std::string>& log);

int main(int argc, char** argv) {
    if (argc < 3) { fprintf(stderr, "kullanim: host_cli <in> <out> [secenekler]\n"); return 2; }
    std::string in = argv[1], out = argv[2];
    Options opt;
    opt.default_type = 0;
    for (int i = 3; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--all") opt.all = true;
        else if (a == "--vmadv") opt.vm_adv = true;
        else if (a == "--vmn" && i + 1 < argc) opt.vmn = atoi(argv[++i]);
        else if (a == "--sdkonly") opt.sdk_only = true;
        else if (a == "--strength" && i + 1 < argc) opt.mut_strength = atoi(argv[++i]);
        else if (a == "--antidebug") opt.antidebug = true;
        else if (a == "--lic-key" && i + 1 < argc) opt.lic_pubkey = argv[++i];
        else if (a == "--lic-pc" && i + 1 < argc) opt.lic_prodcode = argv[++i];
        else if (a == "--lic-wm" && i + 1 < argc) opt.lic_watermark = argv[++i];
        else if (a == "--lic-url" && i + 1 < argc) opt.lic_url = argv[++i];  /* cp273 PORT E */
        else if (a == "--iat") opt.iat_prot = true;         /* cp277: import korumasi CLI (repro) */
        else if (a == "--iatloader") opt.iat_loader_exp = true; /* cp277: DENEYSEL loader-IAT */
        else if (a == "--strenc") opt.strenc = true;        /* cp273: kapsam testi */
        else if (a == "--memprot") opt.memprot = true;      /* cp273: Port D testi */
        else if (a == "--dwarf") opt.dwarf = true;   /* cp275: DWARF kesfi acik */
        else if (a == "--nosdk") opt.sdk_scan = false;
        else if (a == "--dotnet") opt.dotnet = true;
        else if (a == "--nodotnet") opt.dotnet = false;
    }
    if (!opt.all && opt.funcs.empty() && opt.manual.empty()) opt.all = true;
    std::vector<std::string> log;
    int rc = protect(in, out, opt, log);
    for (size_t i = 0; i < log.size(); i++) printf("%s\n", log[i].c_str());
    printf("rc=%d\n", rc);
    return rc;
}
