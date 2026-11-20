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
        else if (a == "--type" && i + 1 < argc) {           /* cp287: 0=V 1=M 2=U (default_type) */
            int t = atoi(argv[++i]); if (t >= 0 && t <= 2) opt.default_type = t;
        }
        else if (a == "--func" && i + 1 < argc) {           /* cp287: RVA (hex) — secili fonksiyon */
            std::string fv = argv[++i];
            opt.funcs.push_back(fv);
            char* end; unsigned long r = strtoul(fv.c_str(), &end, 16);
            if (end != fv.c_str() && r != 0) {
                char k[32]; snprintf(k, sizeof k, "%lX", r);
                opt.ftypes[std::string(k)] = opt.default_type;
            }
        }
        else if (a == "--pack") opt.pack = true;            /* cp287: cpPack LZMA (XPK1) */
        else if (a == "--stripfix") opt.strip_fixups = true;  /* cpStripFixups */
        else if (a == "--stripdbg") opt.strip_debug = true;   /* cpStripDebugInfo */
        else if (a == "--manual" && i + 2 < argc) {         /* cp287: Base End [tip] — UI Add Function esdegeri */
            ManFn m;
            m.rva = (u32)strtoul(argv[++i], NULL, 16);
            m.size = (u32)strtoul(argv[++i], NULL, 16);
            m.ty = -1;   /* tip parse sonunda --type ile baglanir (cp287) */
            opt.manual.push_back(m);
        }
        else if (a == "--vmadv") opt.vm_adv = true;
        else if (a == "--vmsize") opt.vm_size_mode = 1;   /* cp287/P3 VMP-compat boyut */
        else if (a == "--vmn" && i + 1 < argc) { opt.vmn = atoi(argv[++i]); if (opt.vmn < 1) opt.vmn = 1; if (opt.vmn > 10) opt.vmn = 10; } /* cp286: Instances 1..10 */
        else if (a == "--sdkonly") opt.sdk_only = true;
        else if (a == "--strength" && i + 1 < argc) opt.mut_strength = atoi(argv[++i]);
        else if (a == "--antidebug") opt.antidebug = true;
        else if (a == "--lic-key" && i + 1 < argc) opt.lic_pubkey = argv[++i];
        else if (a == "--lic-pc" && i + 1 < argc) opt.lic_prodcode = argv[++i];
        else if (a == "--lic-wm" && i + 1 < argc) opt.lic_watermark = argv[++i];
        else if (a == "--lic-url" && i + 1 < argc) opt.lic_url = argv[++i];  /* cp273 PORT E */
        else if (a == "--iat") opt.iat_prot = true;         /* cp277: import korumasi CLI (repro) */
        else if (a == "--iatloader") opt.iat_loader_exp = true; /* cp277: DENEYSEL loader-IAT */
        else if (a == "--checkvm") opt.checkvm = true;
        else if (a == "--iatdisk") opt.iat_disk = true;   /* cp280: DENEYSEL disk-IAT silme (varsayilan KAPALI) */      /* cp279: UI-checkvm esdegeri (E2E kanit) */
        else if (a == "--antidebug") opt.antidebug = true;  /* cp279: UI-antidebug esdegeri */
        else if (a == "--rt") { opt.rt_selfcrc = opt.rt_textcrc = opt.rt_filecrc = opt.rt_exit = true; } /* cp278: UI-runtime esdegeri (repro) */
        else if (a == "--rtnoexit") opt.rt_exit = false;   /* cp282 (x2): tetik -> kapatma yok (devam) */
        else if (a == "--strenc") opt.strenc = true;        /* cp273: kapsam testi */
        else if (a == "--memprot") opt.memprot = true;      /* cp273: Port D testi */
        else if (a == "--dwarf") opt.dwarf = true;   /* cp275: DWARF kesfi acik */
        else if (a == "--nosdk") opt.sdk_scan = false;
        else if (a == "--dotnet") opt.dotnet = true;
        else if (a == "--nodotnet") opt.dotnet = false;
    }
    if (!opt.all && opt.funcs.empty() && opt.manual.empty()) opt.all = true;
    /* cp287: --manual satirlari --type ONCESI de gelmis olabilir — parse
       sonrasi tipleri guncelle (UI'daki Add Function combo esdegeri) */
    for (auto& m : opt.manual)
        if (m.ty < 0 || m.ty > 2) m.ty = opt.default_type;
    std::vector<std::string> log;
    int rc = protect(in, out, opt, log);
    for (size_t i = 0; i < log.size(); i++) printf("%s\n", log[i].c_str());
    printf("rc=%d\n", rc);
    return rc;
}
