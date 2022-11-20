# APC注入

## 介绍

有关APC相关信息在[MSDN文档](https://learn.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls)上有详细的解释。

> 异步过程调(Asynchronous Procedure Calls, APC)是在特定线程的上下文中异步执行的函数。 当 APC 排队到线程时，系统会发出软件中断。下次计划线程时，它将运行 APC 函数。 系统生成的 APC 称为内核模式 APC。 应用程序生成的 APC 称为用户模式 APC。线程必须处于可警报状态才能运行用户模式 APC。

简单来说就是通过调用`QuenueUserApc`函数将APC添加到指定线程的APC队列中，等待线程调用`SleepEx`, `SignalObjectAndWait`, `MsgWaitForMultipleObjectsEx`, `WaitForMultipleObjectsEx`, or `WaitForSingleObjectEx`函数时进入可警报状态将会执行APC，从而调用的APC的回调函数。

## 基础知识

### QueueUserAPC函数

```C++
DWORD QueueUserAPC(
  [in] PAPCFUNC  pfnAPC,  // APC回调函数指针
  [in] HANDLE    hThread, // 线程的句柄。
  [in] ULONG_PTR dwData   // 传递给回调函数的参数
);
```

### PAPCFUNC回调函数

```C++
PAPCFUNC Papcfunc;

void Papcfunc(
  [in] ULONG_PTR Parameter // 使用 QueueUserAPC函数的dwData参数传递给函数的数据
)
{...}
```

## APC进程注入

APC注入和远程线程注入写入数据部分是一样的，区别是启动线程部分的代码。

### 流程

1. 调用`CreateToolhelp32Snapshot`获取目标进程线程集合
2. 调用`OpenProcess`获取目标进程句柄
3. 调用`VirtualAllocEx`在目标进程中申请内存空间
4. 调用`WriteProcessMemory`向目标进程内存中写入数据
5. 调用`VirtualProtectEx`修改目标进程中的内存属性
6. 调用`QueueUserAPC`向目标进程所有线程插入APC

最后就等待目标进程调用`Sleep`、`WaitForSingleObjectEx`等函数来触发执行注入的代码。

## Eearly Bird

所谓的`Early Bird`算APC注入技术的变种，由于线程初始化时会调用`ntdll`未导出函数`NtTestAlert`，该函数会清空并处理APC队列，而该操作是在进入程序入口点已经执行的，所以可以避免一些杀软的检测。

### 流程

1. 调用`CreateProcess`创建一个挂起的进程
2. 调用`VirtualAllocEx`在挂起的进程内申请一块内存空间
3. 调用`WriteProcessMemory`向挂起进程内存中写入数据
4. 调用`VirtualProtectEx`修改挂起进程中的内存属性
5. 调用`QueueUserAPC`向挂起进程的主线程插入APC
6. 调用`ResumeThread`恢复挂起进程的主线程

进程恢复线程后会调用`NtTestAlert`来执行APC。

## NtTestAlert

在前面知道了可以利用`NtTestAlert`函数会清空APC队列来执行回调函数，所以在做免杀时可以使用该方法来执行代码。

### 流程

1. 调用`VirtualAlloc`在申请一块内存空间
2. 向该内存写入数据
3. 调用`VirtualProtect`修改内存属性RW -> RE
4. 调用`QueueUserAPC`插入APC
5. 调用`NtTestAlert`来清空APC队列

## CreateThread + APC

通过前面的`Early Bird`可以知道将挂起进程的线程恢复后会调用`NtTestAlert`来执行APC，那通过创建新的挂起线程再恢复同样应该也能达到一样的效果。

1. 申请空间写入shellcode
2. 调用`CreateThread`创建一个挂起线程，线程函数指针指向一个正常函数
3. 调用`QueueUserAPC`插入APC，APC回调函数指针指向shellcode
4. 调用`ResumeThread`恢复挂起线程

这和恢复挂起进程的主线程原理一样，调用`ResumeThread`恢复线程后会调用`NtTestAlert`来清空APC队列。使用了`CreateThread`和`ResumeThread`来替换了`Sleep`、`WaitForSingleObject`函数来触发APC。

## APC注入修改版

从前面几种方法中可以知道，可以通过`ResumeThread`来会恢复线程继而调用`NtTestAlert`来执行APC，所以可以利用`SuspendThread`来先挂起目标进程的线程，然后再调用`ResumeThread`来恢复线程从而触发APC。

### 流程

1. 向目标进程中写入shellcode
2. 调用`QueueUserAPC`向挂起进程的主线程插入APC
3. 调用`SuspendThread`挂起线程
4. 调用`ResumeThread`恢复挂起线程

这样就不用去等待目标进程调用`Sleep`、`WaitForSingleObject`函数就可以直接快速触发APC。

## 参考资料

> https://learn.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls
