/* mini3.c — imports VAR, TLS-callback YOK, CRT yok */
extern void __stdcall Sleep(unsigned ms);
extern void __stdcall ExitProcess(unsigned code);
__attribute__((noinline)) int work(int a, int b, int c) { Sleep(1); return a + b * c; }
__attribute__((noinline)) int fib(int n) { return n < 2 ? n : fib(n-1) + fib(n-2); }
void mainCRTStartup(void) {
    volatile int r = work(2, 3, 7) + fib(12);
    (void)r;
    ExitProcess((unsigned)(r == 167 ? 42 : 1));
}
