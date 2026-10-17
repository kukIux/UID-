#pragma once
#include "filter.h"
#include <poll.h>
#include <sys/socket.h>
#include <cstring>

namespace uid_filter::notification {
struct Hello { uint32_t version=1, pid=0, tid=0, uid=0; };
// The companion arms task observation before any irreversible filter install.
inline bool transfer(int socket, void* data, size_t size, bool sending) {
    auto* bytes=static_cast<char*>(data);
    while(size) {
        pollfd descriptor{socket,static_cast<short>(sending?POLLOUT:POLLIN),0};
        int ready;
        do {ready=poll(&descriptor,1,3000);}while(ready<0&&errno==EINTR);
        if(ready<=0)return false;
        const ssize_t n=sending?send(socket,bytes,size,MSG_NOSIGNAL):recv(socket,bytes,size,0);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)return false;
        bytes+=n;size-=size_t(n);
    }
    return true;
}
inline bool prepare(int socket,uint32_t uid) {
    Hello hello{1,uint32_t(getpid()),uint32_t(gettid()),uid};char ready=0;
    return transfer(socket,&hello,sizeof(hello),true)&&transfer(socket,&ready,1,false)&&ready=='R';
}
inline bool send_listener(int socket,int fd) {
    char byte='F';alignas(cmsghdr) char control[CMSG_SPACE(sizeof(fd))]{};
    iovec payload{&byte,1};msghdr message{};
    message.msg_iov=&payload;message.msg_iovlen=1;message.msg_control=control;message.msg_controllen=sizeof(control);
    auto* header=CMSG_FIRSTHDR(&message);header->cmsg_level=SOL_SOCKET;header->cmsg_type=SCM_RIGHTS;
    header->cmsg_len=CMSG_LEN(sizeof(fd));memcpy(CMSG_DATA(header),&fd,sizeof(fd));
    ssize_t result;do{result=sendmsg(socket,&message,MSG_NOSIGNAL);}while(result<0&&errno==EINTR);
    return result==1;
}
inline std::vector<sock_filter> rule(uint32_t self) {
    std::vector<sock_filter> code={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_AARCH64,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_clone,6,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_clone3,5,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_seccomp,4,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_prctl,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PR_SET_SECCOMP,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_USER_NOTIF),
    };
    auto queries=make_rule(self,{},true);
    for(auto& op:queries)if(op.code==(BPF_RET|BPF_K)&&op.k==(SECCOMP_RET_ERRNO|ESRCH))op.k=SECCOMP_RET_USER_NOTIF;
    code.insert(code.end(),queries.begin(),queries.end());return code;
}
inline int install(const std::vector<sock_filter>& code) {
    sock_fprog program{static_cast<unsigned short>(code.size()),const_cast<sock_filter*>(code.data())};
    return syscall(__NR_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,&program);
}
void companion(int client);
}
