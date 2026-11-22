// test64.c — VMP'siz temiz test oyunu (kullanici senaryosu: Test.exe 64-bit)
// w/a/s/d hareket + WrapPos sinir-sarma; 5 fonksiyon export'lu (VMP SDK gibi)
#include <windows.h>
#include <stdio.h>

static int px = 40, py = 12, score = 0, lives = 3, food = 82;

__declspec(dllexport) void WrapPos(int* x, int* y) {
    if (*x < 0) *x += 80;
    if (*x >= 80) *x -= 80;
    if (*y < 0) *y += 24;
    if (*y >= 24) *y -= 24;
}
__declspec(dllexport) void MovePlayer(int dx, int dy) {
    px += dx; py += dy;
    WrapPos(&px, &py);
    score += 1;
}
__declspec(dllexport) void GhostStep(int* gx, int* gy) {
    *gx = (*gx + 1) % 80;
    WrapPos(gx, gy);
}
__declspec(dllexport) int CheckCollision(int x, int y) {
    return x == px && y == py;
}
__declspec(dllexport) void GameTick(char cmd) {
    int gx = 10, gy = 5;
    if (cmd == 'w') MovePlayer(0, -1);
    else if (cmd == 's') MovePlayer(0, 1);
    else if (cmd == 'a') MovePlayer(-1, 0);
    else if (cmd == 'd') MovePlayer(1, 0);
    GhostStep(&gx, &gy);
    if (CheckCollision(gx, gy)) { lives--; food--; }
}

int main(void) {
    char line[64];
    for (;;) {
        printf("Komut > ");
        if (!fgets(line, sizeof line, stdin)) break;
        for (char* p = line; *p; ++p) GameTick(*p);
        printf("Skor: %d   Can: %d   Kalan yem: %d\n", score, lives, food);
    }
    printf("Giris bitti (EOF), oyun kapatiliyor.\n");
    return 0;
}
