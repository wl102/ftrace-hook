//go build: ignore

/*
 * Hooking kernel functions using ftrace framework
 *
 * Copyright (c) 2018 ilammy
 */

#define pr_fmt(fmt) "ftrace_hook: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/init.h>
#include <linux/types.h>
#include <net/sock.h>
#include <net/netlink.h>
//#include <linux/wait.h>

MODULE_DESCRIPTION("Example module hooking clone() and execve() via ftrace");
MODULE_AUTHOR("ilammy <a.lozovsky@gmail.com> wangzhen <wanglian.163.com>");
MODULE_LICENSE("GPL");

#define NETLINK_TEST 25
#define MAX_MSGSIZE 1024
int stringlength(char *s);

static DECLARE_COMPLETION(msg_received);
static uint32_t msg_seq = 0;
static uint32_t ENABLE = 0; 

struct sock *nl_sk = NULL;

/**
 * sec 3
 */
#define MAX_MSGS 1024

//static DECLARE_WAIT_QUEUE_HEAD(wq);
//static int flag = 0;
static spinlock_t lock;

struct msg_info {
    int seqid;
    char *payload;
	struct completion comp;
};
static struct msg_info msg_buffer[MAX_MSGS];

//向用户态进程回发消息
static int sendnlmsg(char *message, int pid)
{
    struct sk_buff *skb_1;
    struct nlmsghdr *nlh;
    int len = NLMSG_SPACE(MAX_MSGSIZE);
    int slen = 0;
	int sqid, head;
    if(!message || !nl_sk)
    {
        return -1;
    }
    printk(KERN_ERR "pid:%d\n",pid);
    skb_1 = alloc_skb(len,GFP_KERNEL);
    if(!skb_1)
    {
        printk(KERN_ERR "my_net_link:alloc_skb error\n");
    }
    slen = stringlength(message);
    nlh = nlmsg_put(skb_1,0,0,NLMSG_DONE,MAX_MSGSIZE,0);
    NETLINK_CB(skb_1).portid = 0;
    NETLINK_CB(skb_1).dst_group = 0;
    message[slen]= '\0';

    // 设置唯一的seqid
	msg_seq++;
    nlh->nlmsg_seq = msg_seq;
	sqid = msg_seq;
    memcpy(NLMSG_DATA(nlh),message,slen+1);
    printk("my_net_link:send message '%s' %d.\n",(char *)NLMSG_DATA(nlh), sqid);
	// 发送消息
    netlink_unicast(nl_sk,skb_1,pid,MSG_DONTWAIT);

    // 如何检测程序准备就绪，才开始等待用户态的响应
	if (ENABLE) {
		// 等待接收消息回调
		//wait_event_interruptible(wq, flag != 0);
		head = sqid % MAX_MSGS;

		// spin_lock(&lock);
        // init_completion(&msg_buffer[head].comp);
        // spin_unlock(&lock);

		//等待消息完成
		//wait_for_completion(&msg_buffer[head].comp);
		if (!wait_for_completion_interruptible_timeout(&msg_buffer[head].comp, msecs_to_jiffies(200))) {
			return 1;
		}
		
		spin_lock(&lock);
		//flag = 0;
		// 从缓冲区读取接收到的seqid
		if (msg_buffer[head].seqid != sqid) {
			pr_info("head is:%d seqid not equal: %d!=%d\n", head,msg_buffer[head].seqid,sqid);
			return 1;
		}
		if (strcmp(msg_buffer[head].payload, "0") == 0 && msg_buffer[head].seqid == sqid) {
			spin_unlock(&lock);
			return 1;
		}
		spin_unlock(&lock);
	}
	return 0;
}
int stringlength(char *s)
{
    int slen = 0;
    for(; *s; s++)
    {
        slen++;
    }
    return slen;
}
//接收用户态发来的消息
void nl_data_ready(struct sk_buff *__skb)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	char str[10];
	//int pid;
	//printk("begin data_ready\n");
	skb = skb_get(__skb);
	if(skb->len >= NLMSG_SPACE(0))
	{
		nlh = nlmsg_hdr(skb);
		memcpy(str, NLMSG_DATA(nlh), sizeof(str));
		//启用
		if (strcmp(str, "2") == 0) {
			ENABLE = 1;
			return;
		}
		//退出
		if (strcmp(str, "3") == 0) {
			ENABLE = 0;
			return;
		}
		printk("Message received:%d,%s\n",nlh->nlmsg_seq, str) ;
		//pid = nlh->nlmsg_pid;
		
		if (ENABLE) {
			spin_lock(&lock);
			msg_buffer[(nlh->nlmsg_seq % MAX_MSGS)].seqid = nlh->nlmsg_seq;
			memcpy(msg_buffer[(nlh->nlmsg_seq % MAX_MSGS)].payload, str, 8);
			pr_info("set seq status:%d,%s\n", msg_buffer[(nlh->nlmsg_seq % MAX_MSGS)].seqid, msg_buffer[(nlh->nlmsg_seq % MAX_MSGS)].payload);
			// 设置标志
			//flag = 1;
			complete(&msg_buffer[(nlh->nlmsg_seq % MAX_MSGS)].comp);
			spin_unlock(&lock);
			// 唤醒等待队列
			//wake_up_interruptible(&wq);
		}

		kfree_skb(skb);
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0) return 0;
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}


/**
 *  centos7 need declate this function with manual
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
static inline bool within_module(unsigned long addr, const struct module *mod)
{
	return within_module_init(addr, mod) || within_module_core(addr, mod);
}
#endif

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long)hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
#endif
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_clone)(struct pt_regs *regs);

static asmlinkage long fh_sys_clone(struct pt_regs *regs)
{
	long ret;

	pr_info("clone() before\n");

	ret = real_sys_clone(regs);

	pr_info("clone() after: %ld\n", ret);

	return ret;
}
#else
static asmlinkage long (*real_sys_clone)(unsigned long clone_flags,
		unsigned long newsp, int __user *parent_tidptr,
		int __user *child_tidptr, unsigned long tls);

static asmlinkage long fh_sys_clone(unsigned long clone_flags,
		unsigned long newsp, int __user *parent_tidptr,
		int __user *child_tidptr, unsigned long tls)
{
	long ret;

	pr_info("clone() before\n");

	ret = real_sys_clone(clone_flags, newsp, parent_tidptr,
		child_tidptr, tls);

	pr_info("clone() after: %ld\n", ret);

	return ret;
}
#endif

static char *duplicate_filename(const char __user *filename)
{
	char *kernel_filename;

	kernel_filename = kmalloc(4096, GFP_KERNEL);
	if (!kernel_filename)
		return NULL;

	if (strncpy_from_user(kernel_filename, filename, 4096) < 0) {
		kfree(kernel_filename);
		return NULL;
	}

	return kernel_filename;
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_execve)(struct pt_regs *regs);

static asmlinkage long fh_sys_execve(struct pt_regs *regs)
{
	long ret;
	char *kernel_filename;
    struct path path;
    char *buf;
    char *absolute_path;
    int buflen = 512;

	kernel_filename = duplicate_filename((void*) regs->di);

	pr_info("execve() before: %s\n", kernel_filename);

    // 将文件名转换为路径
    ret = kern_path(kernel_filename, LOOKUP_FOLLOW, &path);
    if (ret)
    {
        pr_err("kern_path failed\n");
        kfree(kernel_filename);
        return ret;
    }

    // 分配一个缓冲区来存储绝对路径
    buf = kmalloc(buflen, GFP_KERNEL);
    if (!buf)
    {
        pr_err("kmalloc for buf failed\n");
        path_put(&path);
        kfree(kernel_filename);
        return -ENOMEM;
    }

    // 获取绝对路径
    absolute_path = d_path(&path, buf, buflen);
    if (IS_ERR(absolute_path))
    {
        pr_err("d_path failed\n");
        kfree(buf);
        path_put(&path);
        kfree(kernel_filename);
        return PTR_ERR(absolute_path);
    }

    // 打印绝对路径
    pr_info("execve() absolute path: %s\n", absolute_path);

    /**
     * check md5, if ok; goto real_sys_execve else return
     */
	ret = sendnlmsg(absolute_path, 100);
    if (ret) {
        pr_err("Failed to get response from user space\n");
		pr_info("execve() hooked: %ld\n", ret);
        kfree(buf);
        path_put(&path);
        kfree(kernel_filename);
        return -ret;
    }

    // 清理工作
    kfree(buf);
    path_put(&path);
	kfree(kernel_filename);

	ret = real_sys_execve(regs);

	pr_info("execve() after: %ld\n", ret);

	return ret;
}
#else
static asmlinkage long (*real_sys_execve)(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);

static asmlinkage long fh_sys_execve(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp)
{
	long ret;
	char *kernel_filename;
	struct path path;
    char *buf;
    char *absolute_path;
    int buflen = 256;

	// Duplicate the filename from userspace to kernel space
	kernel_filename = duplicate_filename(filename);
	if (!kernel_filename)
        return -ENOMEM;

	pr_info("execve() before: %s\n", kernel_filename);

    // Convert the filename to a path
    ret = kern_path(kernel_filename, LOOKUP_FOLLOW, &path);
    if (ret)
    {
        pr_err("kern_path failed\n");
        kfree(kernel_filename);
        return ret;
    }

    // Allocate a buffer to store the absolute path
    buf = kmalloc(buflen, GFP_KERNEL);
    if (!buf)
    {
        pr_err("kmalloc for buf failed\n");
        path_put(&path);
        kfree(kernel_filename);
        return -ENOMEM;
    }

    // Get the absolute path
    absolute_path = d_path(&path, buf, buflen);
    if (IS_ERR(absolute_path))
    {
        pr_err("d_path failed\n");
        kfree(buf);
        path_put(&path);
        kfree(kernel_filename);
        return PTR_ERR(absolute_path);
    }

    // Print the absolute path
    pr_info("execve() absolute path: %s\n", absolute_path);

    /**
     * check md5, if ok; goto real_sys_execve else return
     */
	// netlink
	ret = sendnlmsg(absolute_path, 100);
    if (ret) {
        pr_err("Failed to get response from user space\n");
		pr_info("execve() hooked: %ld\n", ret);
        kfree(buf);
        path_put(&path);
        kfree(kernel_filename);
        return -ret;
    }

	// Clean up
    kfree(buf);
    path_put(&path);
    kfree(kernel_filename);

	ret = real_sys_execve(filename, argv, envp);

	pr_info("execve() after: %ld\n", ret);

	return ret;
}
#endif

/*
 * x86_64 kernels have a special naming convention for syscall entry points in newer kernels.
 * That's what you end up with if an architecture has 3 (three) ABIs for system calls.
 */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original)	\
	{					\
		.name = SYSCALL_NAME(_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

static struct ftrace_hook demo_hooks[] = {
	//HOOK("sys_clone",  fh_sys_clone,  &real_sys_clone),
	HOOK("sys_execve", fh_sys_execve, &real_sys_execve),
};

static int fh_init(void)
{
	int err;
	int i =0;
	struct netlink_kernel_cfg cfg = {
        .input = nl_data_ready,
    };

	err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (err)
		return err;

	pr_info("module loaded\n");

	// 手动初始化 msg_buffer
    for (; i < MAX_MSGS; i++) {
        msg_buffer[i].seqid = i;
        //memset(msg_buffer[i].payload, 0, sizeof(msg_buffer[i].payload));
		msg_buffer[i].payload = kmalloc(8, GFP_KERNEL);
		init_completion(&msg_buffer[i].comp);
    }

    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
    if(!nl_sk){
        printk(KERN_ERR "my_net_link: create netlink socket error.\n");
        return 1;
    }
    printk("my_net_link_4: create netlink socket ok.\n");
	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	int i;
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));

	pr_info("module unloaded\n");
    if (nl_sk) {
        netlink_kernel_release(nl_sk);
    }
	
    for (i = 0; i < MAX_MSGS; i++) {
        kfree(msg_buffer[i].payload);
    }
    printk("my_net_link: self module exited\n");
}
module_exit(fh_exit);
