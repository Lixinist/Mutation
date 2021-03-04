# Mutation

为了学习C/C++/x86ASM和代码混淆而写的一个作品。
对x86EXE和DLL进行代码变异和代码乱序保护。
混淆规则包括mov，push，pop，add，sub，xor，rcl，rcr，or，and，lea，test，所有jcc，call。
PS：暂时只测试了部分MSVC编译的程序，没有大规模测试。

开发环境：VS2019，C/C++，x86编译。

用到的库：capstone（反汇编引擎），asmjit（汇编引擎），cyxvc的部分PE库。

相关文章及其思路：
https://blog.csdn.net/qq_15059515/article/details/114363427

