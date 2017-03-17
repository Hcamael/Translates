# 使用Pin进行污点分析与模式匹配


**作者：**[Jonathan Salwan](http://twitter.com/JonathanSalwan)
---

上周我在研究Pin的API，这篇文章作为我个人的思考笔记。这篇文章的所有例子都仅仅是个PoC，因此不是100%都可以运行。但是能给人灵感。

## 目录:
* [1 - 介绍](#介绍)
  * [1.1 - 概念](#概念)
  * [1.2 - 什么是污点](#什么是污点)
    * [1.2.1 - 动态分析](#动态分析)
    * [1.2.2 - 静态分析](#静态分析)
    * [1.2.3 - 动态还是静态?](#动态还是静态?)
  * [1.3 - 一些问题](#一些问题)
    * [1.3.1 - 字节还是比特?](#字节还是比特?)


# 介绍
## 概念
污点分析是一种流行的方法，其包含了检查用户输入的变量哪些被修改过。所有用户输入如果没有经过正确的检查，都是危险的。使用污点分析方法去检查寄存器和内存区域哪些被用户控制了当程序崩溃时 - 这可能是有用的。

![memory.png](memory.png)

要知道一个区域是可读还是可写这是非常容易的。但是要去检查哪些区域是用户可控的和哪些区域被污点传播过了，这是非常困难的。比如，看下面代码:
```c
/* Example 1 */
void foo1(const char *av[])
{
  uint32_t a, b;

  a = atoi(av[1]);
  b = a;
  foo2(b);
}

/* Example 2 */
void foo2(const char *av[])
{
  uint8_t *buffer;

  if (!(buffer = (uint8_t *)malloc(32 * sizeof(uint8_t))))
    return(-ENOMEM);

  buffer[2]  = av[1][4];
  buffer[12] = av[1][8];
  buffer[30] = av[1][12];
}
```

在第一个例子中，一开始变量`a`和`b`并不是污点。当`atoi`函数被调用时，变量`a`被污染了。然后当变量`b`被分配了变量`a`的值后也被污染了。现在我们能知道`foo2`函数的两个参数都是用户可控的。

在第二个例子中，当`buffer`被`malloc`函数分配内存时并不是污点。之后，当被分配的区域被用户输入初始化时，我们需要污染`buffer+2`, `buffer+12`, `buffer+30`这3个字节。之后，当其中一个，两个或者所有字节被读时，我们可以得知读取这些字节的地方是用户可控的。

## 什么是污点
我们有两种可使用的方式，静态或动态分析。从这两种方式，我们能找到一些他们的优点和缺点。

### 动态分析
使用动态分析，基本上我们需要确定所有的用户输入，比如环境变量和系统调用。当我们遇到这些指令时，比如GET/PUT, LOAD/STORE，我们开始污染这些输入和传播或移除污点。

![input_in_binary.png](input_in_binary.png)

为了进行动态分析，我们需要一个动态二进制插桩框架(简称DBI)。DBI的目的是在每个指令间增加pre/post句柄。当一个句柄被调用时，你能够获取到所有你想知道的关于指令或环境(内存)的所有信息。

有一些工具提供一个叫中介码(IR)的数据结构。例如，[Valgrind](http://valgrind.org/)是一个受欢迎使用IR(Vex)的插桩框架。通常使用IR，每个变量都是处于静态单赋值形式([Static Single Assignment Form](http://en.wikipedia.org/wiki/Static_single_assignment_form))，这能更简单去标记污点和管理你的内存。下面有一个例子，是关于VEX和SSA form的，下面的代码是Vex用来代替`add eax, ebx`指令的替代表示。
```
t3 = GET:I32(0)     # get %eax, a 32-bit integer (t3 = eax)
t2 = GET:I32(12)    # get %ebx, a 32-bit integer (t2 = ebx) 
t1 = Add32(t3,t2)   # eger (t2 = ebx)
PUT(0) = t1         put %eax (eax = t1)
```

我选择使用[Pin](http://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool)： 一个由Intel用C++开发的动态二进制插桩框架(不使用IR)。
### 静态分析
### 动态还是静态?
## 一些问题
### 字节还是比特?