// ============================================================
// muttest.cpp — motor CLI test koşumu (Linux/wine bagimsiz)
// Kullanim:
//   ./muttest <girdi.exe> <cikti.exe> <V|M|U> [guc 1..3] [ad:TIP ...]
// Ornegin:
//   ./muttest Test.exe Test_M_vmp.exe M 2
//   ./muttest Test.exe Test_mix.exe V 2 WrapPos:M MovePlayer:U
// ============================================================
#include "engine.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

int main(int argc, char** argv) {
    if (argc < 4) {
        printf("kullanim: %s <in> <out> <V|M|U> [strength] [ad:TIP ...]\n", argv[0]);
        return 2;
    }
    Options o;
    std::string in = argv[1], out = argv[2];
    std::string ty = argv[3];
    o.default_type = (ty == "M") ? 1 : (ty == "U" ? 2 : 0);
    if (argc > 4) o.mut_strength = atoi(argv[4]);
    for (int i = 5; i < argc; i++) {
        std::string s = argv[i];
        size_t c = s.find_last_of(':');
        if (c == std::string::npos) { o.funcs.push_back(s); continue; }
        std::string name = s.substr(0, c);
        std::string t = s.substr(c + 1);
        int tv = (t == "M") ? 1 : (t == "U" ? 2 : 0);
        o.funcs.push_back(name);
        o.ftypes[name] = tv;
    }
    std::vector<std::string> log;
    int rc = protect(in, out, o, log);
    for (auto& l : log) printf("%s\n", l.c_str());
    printf("rc=%d\n", rc);
    return rc;
}
