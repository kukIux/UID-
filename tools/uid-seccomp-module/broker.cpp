#include "notification.h"
#include "fork_events.h"
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <map>
#include <memory>
#include <cstdio>
#include <cstring>

namespace uid_filter::notification {
namespace {
using Program=std::vector<sock_filter>;
using Policies=std::vector<std::shared_ptr<const Program>>;
struct State {
    int count=-1,tracer=-1;
    std::shared_ptr<const Program> pending;
    Policies installed;
};
struct Identity {int tgid=-1,uid=-1,count=-1,tracer=-1;};
bool status(int tid,Identity& result) {
    char path[64];snprintf(path,sizeof(path),"/proc/%d/status",tid);
    FILE* file=fopen(path,"re");if(!file)return false;
    char line[256];
    while(fgets(line,sizeof(line),file)) {
        if(sscanf(line,"Tgid: %d",&result.tgid)==1)continue;
        if(sscanf(line,"Uid: %d",&result.uid)==1)continue;
        if(sscanf(line,"Seccomp_filters: %d",&result.count)==1)continue;
        sscanf(line,"TracerPid: %d",&result.tracer);
    }
    fclose(file);return result.tgid>0&&result.count>=0&&result.tracer>=0;
}
bool read_memory(int tid,uint64_t address,void* output,size_t size) {
    iovec local{output,size},remote{reinterpret_cast<void*>(address),size};
    return process_vm_readv(tid,&local,1,&remote,1,0)==ssize_t(size);
}
bool evaluate(const Program& program,const seccomp_data& data,uint32_t& result) {
    uint32_t a=0,x=0,memory[BPF_MEMWORDS]{};
    for(size_t pc=0;pc<program.size();++pc) {
        const auto& op=program[pc];const uint32_t v=BPF_SRC(op.code)==BPF_X?x:op.k;
        switch(BPF_CLASS(op.code)) {
        case BPF_LD:case BPF_LDX: {
            uint32_t value;
            if(BPF_MODE(op.code)==BPF_IMM)value=op.k;
            else if(BPF_MODE(op.code)==BPF_LEN)value=sizeof(data);
            else if(BPF_MODE(op.code)==BPF_MEM&&op.k<BPF_MEMWORDS)value=memory[op.k];
            else if(BPF_CLASS(op.code)==BPF_LD&&BPF_MODE(op.code)==BPF_ABS&&BPF_SIZE(op.code)==BPF_W&&op.k<=sizeof(data)-4)
                memcpy(&value,reinterpret_cast<const char*>(&data)+op.k,4);
            else return false;
            if(BPF_CLASS(op.code)==BPF_LD)a=value;else x=value;break;
        }
        case BPF_ST:if(op.k>=BPF_MEMWORDS)return false;memory[op.k]=a;break;
        case BPF_STX:if(op.k>=BPF_MEMWORDS)return false;memory[op.k]=x;break;
        case BPF_ALU:
            switch(BPF_OP(op.code)) {
            case BPF_ADD:a+=v;break;case BPF_SUB:a-=v;break;case BPF_MUL:a*=v;break;
            case BPF_DIV:if(!v){result=0;return true;}a/=v;break;
            case BPF_MOD:if(!v){result=0;return true;}a%=v;break;
            case BPF_OR:a|=v;break;case BPF_AND:a&=v;break;case BPF_XOR:a^=v;break;
            case BPF_LSH:a=v<32?a<<v:0;break;case BPF_RSH:a=v<32?a>>v:0;break;
            case BPF_NEG:a=0-a;break;default:return false;
            }break;
        case BPF_JMP: {
            size_t skip;
            switch(BPF_OP(op.code)) {
            case BPF_JA:skip=op.k;break;case BPF_JEQ:skip=a==v?op.jt:op.jf;break;
            case BPF_JGT:skip=a>v?op.jt:op.jf;break;case BPF_JGE:skip=a>=v?op.jt:op.jf;break;
            case BPF_JSET:skip=(a&v)?op.jt:op.jf;break;default:return false;
            }
            if(skip>=program.size()-pc)return false;pc+=skip;break;
        }
        case BPF_RET:result=BPF_RVAL(op.code)==BPF_A?a:op.k;return true;
        case BPF_MISC:
            if(BPF_MISCOP(op.code)==BPF_TAX)x=a;else if(BPF_MISCOP(op.code)==BPF_TXA)a=x;else return false;
            break;
        default:return false;
        }
    }
    return false;
}
class Session {
    struct Event {bool fork;uint32_t tid,parent;uint64_t time;};
    std::map<int,State> states_;
    std::map<int,std::unique_ptr<ForkEvents>> watches_;
    bool healthy_=true;
    bool watch(int tid) {
        if(watches_.count(tid))return true;
        if(watches_.size()>=128)return false;
        auto events=std::make_unique<ForkEvents>();if(!events->open(tid))return false;
        watches_[tid]=std::move(events);return true;
    }
    bool births() {
        std::vector<Event> events;
        for(auto& watch:watches_) {
            if(!watch.second->drain([&](bool fork,uint32_t tid,uint32_t parent,uint32_t,uint64_t time){events.push_back({fork,tid,parent,time});}))return false;
        }
        std::stable_sort(events.begin(),events.end(),[](const auto& a,const auto& b){return a.time<b.time;});
        for(const auto& event:events) {
            if(event.fork) {
                const auto parent=states_.find(event.parent);
                if(parent==states_.end())return false;
                // Snapshot the actual creating thread, not the process leader.
                // Immutable programs are shared; each child gets its own list.
                State child=parent->second;states_[event.tid]=std::move(child);
                watches_.erase(event.tid);
            } else {states_.erase(event.tid);watches_.erase(event.tid);}
        }
        if(states_.size()>4096)return false;
        return true;
    }
    bool settle(int tid,State& state) {
        if(!state.pending)return true;
        Identity now;if(!status(tid,now))return false;
        if(now.count==state.count+1)state.installed.push_back(state.pending);
        else if(now.count!=state.count)return false;
        state.pending.reset();state.count=now.count;state.tracer=now.tracer;return true;
    }
    bool respond(const seccomp_notif& request,seccomp_notif_resp& response) {
        if(!births())return false;
        auto position=states_.find(request.pid);if(position==states_.end())return false;
        auto& state=position->second;if(!settle(request.pid,state))return false;
        const auto& call=request.data;
        const bool prctl_install=call.nr==__NR_prctl&&uint32_t(call.args[0])==PR_SET_SECCOMP&&uint32_t(call.args[1])==SECCOMP_MODE_FILTER;
        const bool seccomp_install=call.nr==__NR_seccomp&&uint32_t(call.args[0])==SECCOMP_SET_MODE_FILTER;
        if(prctl_install||seccomp_install) {
            // Do not invent a per-thread interpretation of a synchronized policy.
            if(seccomp_install&&(call.args[1]&SECCOMP_FILTER_FLAG_TSYNC))return false;
            Identity now;if(!status(request.pid,now))return false;
            state.count=now.count;state.tracer=now.tracer;
            sock_fprog program{};
            // Invalid pointers/lengths retain the kernel's own rejection.
            if(!read_memory(request.pid,call.args[2],&program,sizeof(program))||!program.len||program.len>BPF_MAXINSNS)return true;
            auto copy=std::make_shared<Program>(program.len);
            if(!read_memory(request.pid,reinterpret_cast<uint64_t>(program.filter),copy->data(),copy->size()*sizeof(sock_filter)))return true;
            state.pending=std::move(copy);return true;
        }
        if(call.nr==__NR_clone||call.nr==__NR_clone3) {
            // Arm this creator before CONTINUE. Its FORK record is published
            // before the new task can send its first notification.
            return watch(request.pid);
        }
        if(call.nr!=__NR_getpriority)return true;
        uint32_t action=SECCOMP_RET_ALLOW;
        for(const auto& program:state.installed) {
            uint32_t result;if(!evaluate(*program,call,result))return false;
            if(int32_t(result&SECCOMP_RET_ACTION_FULL)<int32_t(action&SECCOMP_RET_ACTION_FULL))action=result;
        }
        action&=SECCOMP_RET_ACTION_FULL;
        if(action==SECCOMP_RET_TRACE) {
            if(state.tracer!=0)return false;
            response.flags=0;response.error=-ENOSYS;return true;
        }
        if(action!=SECCOMP_RET_ALLOW&&action!=SECCOMP_RET_LOG)return false;
        response.flags=0;response.error=-ESRCH;return true;
    }
public:
    bool prepare(int tid) {states_[tid]=State{};return watch(tid);}
    void serve(int listener) noexcept {
        for(;;) {
            pollfd descriptor{listener,POLLIN,0};int ready;
            do{ready=poll(&descriptor,1,-1);}while(ready<0&&errno==EINTR);
            if(ready<0||(descriptor.revents&(POLLHUP|POLLERR|POLLNVAL)))break;
            if(!(descriptor.revents&POLLIN))continue;
            seccomp_notif request{};
            if(ioctl(listener,SECCOMP_IOCTL_NOTIF_RECV,&request)) {if(errno==EINTR||errno==ENOENT)continue;break;}
            int valid;
            do{valid=ioctl(listener,SECCOMP_IOCTL_NOTIF_ID_VALID,&request.id);}while(valid<0&&errno==EINTR);
            if(valid)continue;
            seccomp_notif_resp response{};response.id=request.id;response.flags=SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            if(healthy_) {
                try{healthy_=respond(request,response);}catch(...){healthy_=false;}
                if(!healthy_) {
                    // Unknown/lost state must not fabricate ESRCH or prevent
                    // ordinary process creation. Keep draining until task exit.
                    response={};response.id=request.id;response.flags=SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                    states_.clear();watches_.clear();
                }
            }
            int sent;
            do{sent=ioctl(listener,SECCOMP_IOCTL_NOTIF_SEND,&response);}while(sent<0&&errno==EINTR);
            if(sent&&errno!=ENOENT)break;
        }
    }
};
}
void companion(int client) {
    int listener=-1;
    try {
        Hello hello{};ucred peer{};socklen_t length=sizeof(peer);
        if(!transfer(client,&hello,sizeof(hello),false)||hello.version!=1||hello.uid%100000<10000||hello.uid%100000>19999)return;
        if(getsockopt(client,SOL_SOCKET,SO_PEERCRED,&peer,&length)||(peer.pid!=int(hello.pid)&&peer.uid!=0))return;
        Identity identity;if(!status(hello.tid,identity)||identity.tgid!=int(hello.pid)||(identity.uid!=0&&identity.uid!=int(hello.uid)))return;
        Session session;if(!session.prepare(hello.tid))return;
        char ready='R';if(!transfer(client,&ready,1,true))return;
        char byte=0;alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
        iovec payload{&byte,1};msghdr message{};message.msg_iov=&payload;message.msg_iovlen=1;
        message.msg_control=control;message.msg_controllen=sizeof(control);
        pollfd descriptor{client,POLLIN,0};int ready_count;
        do{ready_count=poll(&descriptor,1,-1);}while(ready_count<0&&errno==EINTR);
        if(ready_count<=0)return;
        ssize_t n;do{n=recvmsg(client,&message,MSG_CMSG_CLOEXEC);}while(n<0&&errno==EINTR);
        auto* header=CMSG_FIRSTHDR(&message);
        if(n!=1||!header||header->cmsg_level!=SOL_SOCKET||header->cmsg_type!=SCM_RIGHTS||header->cmsg_len!=CMSG_LEN(sizeof(int)))return;
        memcpy(&listener,CMSG_DATA(header),sizeof(listener));
        if(byte=='F'&&!(message.msg_flags&MSG_CTRUNC))session.serve(listener);
    }catch(...){ }
    if(listener>=0)close(listener);
}
}
