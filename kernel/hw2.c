#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/pid.h>

#define BAN_BIT_GETPID 0
#define BAN_BIT_PIPE 1
#define BAN_BIT_KILL 2
#define BAN_BIT_SIG 3

asmlinkage long sys_hello(void) {
 printk("Hello, World!\n");
 return 0;
}

long set_ban(int ban_getpid, int ban_pipe, int ban_kill, int ban_sig){
    if (ban_getpid < 0 || ban_pipe < 0 || ban_kill < 0 || ban_sig < 0) {
        return -EINVAL;
    }
    if (current_uid().val != 0) {
        return -EPERM;
    }

    if (ban_getpid > 1) ban_getpid = 1;
    if (ban_pipe > 1) ban_pipe = 1;
    if (ban_kill > 1) ban_kill = 1;
    if (ban_sig > 1) ban_sig = 1;

    if(ban_getpid == 1) {
        current->syscall_bans |= (1 << BAN_BIT_GETPID);
    } else{
        current->syscall_bans &= ~(1 << BAN_BIT_GETPID);
    }
    if(ban_pipe == 1) {
        current->syscall_bans |= (1 << BAN_BIT_PIPE);
    } else{
        current->syscall_bans &= ~(1 << BAN_BIT_PIPE);
    }
    if(ban_kill == 1) {
        current->syscall_bans |= (1 << BAN_BIT_KILL);
    } else{
        current->syscall_bans &= ~(1 << BAN_BIT_KILL);
    }
    if(ban_sig == 1) {
        current->syscall_bans |= (1 << BAN_BIT_SIG);
    } else{
        current->syscall_bans &= ~(1 << BAN_BIT_SIG);
    }
    return 0;
}

long get_ban(char ban){
    /*if (current_uid().val != 0) {
        return -EPERM;
    }*/

    switch(ban) {
        case 'g':
            return (current->syscall_bans & (1 << BAN_BIT_GETPID)) ? 1 : 0;
        case 'p':
            return (current->syscall_bans & (1 << BAN_BIT_PIPE)) ? 1 : 0;
        case 'k':
            return (current->syscall_bans & (1 << BAN_BIT_KILL)) ? 1 : 0;
        case 's':
            return (current->syscall_bans & (1 << BAN_BIT_SIG)) ? 1 : 0;
        default:
            return -EINVAL;
    }
}

long check_ban(pid_t pid, char ban) {
    int bitCheck;
    struct task_struct *target;
    switch (ban) {
        case 'g': bitCheck = BAN_BIT_GETPID; break;
        case 'p': bitCheck = BAN_BIT_PIPE; break;
        case 'k': bitCheck = BAN_BIT_KILL; break;
        case 's': bitCheck = BAN_BIT_SIG; break;
        default: return -EINVAL;
    }
    rcu_read_lock();
    target = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (target == NULL){
        rcu_read_unlock();
        return -ESRCH;
    }
    rcu_read_unlock();
    if(current->syscall_bans & (1 << bitCheck)) {
        return -EPERM;
    }
    if(target->syscall_bans & (1 << bitCheck)){
        return 1;
    } else {
        return 0;
    }
}

long flip_ban_branch(int height, char ban){
    /*if (current_uid().val != 0) {
        return -EPERM;
    }*/
    int updateCount = 0;
    int bitCheck;
    struct task_struct *parent_task;
    int i;

    if(height <= 0) {
        return -EINVAL;
    }
    switch (ban) {
        case 'g': bitCheck = BAN_BIT_GETPID; break;
        case 'p': bitCheck = BAN_BIT_PIPE; break;
        case 'k': bitCheck = BAN_BIT_KILL; break;
        case 's': bitCheck = BAN_BIT_SIG; break;
        default: return -EINVAL;
    }

    if(current->syscall_bans & (1 << bitCheck)) {
        return -EPERM;
    }
    
    parent_task = current->real_parent;

    for (i = 0; i < height; i++) {
        if(parent_task->pid == 0) {
            break;
        }
        if(parent_task->syscall_bans & (1 << bitCheck)) {
            parent_task->syscall_bans &= ~(1 << bitCheck);
        } else{
            parent_task->syscall_bans |= (1 << bitCheck);
            updateCount++;


        }
        parent_task = parent_task->real_parent;
    }
    return updateCount;
}
