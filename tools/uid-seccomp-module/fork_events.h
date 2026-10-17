#pragma once
#include <linux/perf_event.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cstdint>
#include <cstring>
#include <vector>

class ForkEvents {
    int fd_=-1;
    void* mapping_=MAP_FAILED;
    size_t mapping_size_=0, data_size_=0, page_=0;
    uint64_t tail_=0;
    void copy(void* out,uint64_t position,size_t length) const {
        const auto* data=static_cast<const char*>(mapping_)+page_;
        const size_t offset=position%data_size_;
        const size_t first=length<data_size_-offset?length:data_size_-offset;
        memcpy(out,data+offset,first);
        if(first<length)memcpy(static_cast<char*>(out)+first,data,length-first);
    }
public:
    ForkEvents()=default;
    ForkEvents(const ForkEvents&)=delete;
    ~ForkEvents(){if(mapping_!=MAP_FAILED)munmap(mapping_,mapping_size_);if(fd_>=0)close(fd_);}
    bool open(int tid) {
        perf_event_attr attr{};attr.size=sizeof(attr);attr.type=PERF_TYPE_SOFTWARE;
        attr.config=PERF_COUNT_SW_DUMMY;attr.task=1;attr.wakeup_events=1;
        fd_=syscall(__NR_perf_event_open,&attr,tid,-1,-1,PERF_FLAG_FD_CLOEXEC);
        if(fd_<0)return false;
        page_=sysconf(_SC_PAGESIZE);data_size_=page_*64;mapping_size_=data_size_+page_;
        mapping_=mmap(nullptr,mapping_size_,PROT_READ|PROT_WRITE,MAP_SHARED,fd_,0);
        return mapping_!=MAP_FAILED;
    }
    int fd() const{return fd_;}
    template<class F> bool drain(F&& event) {
        auto* meta=static_cast<perf_event_mmap_page*>(mapping_);
        const uint64_t head=__atomic_load_n(&meta->data_head,__ATOMIC_ACQUIRE);
        if(head<tail_||head-tail_>data_size_)return false;
        while(tail_<head) {
            perf_event_header header{};
            if(head-tail_<sizeof(header))return false;
            copy(&header,tail_,sizeof(header));
            if(header.size<sizeof(header)||header.size>head-tail_||header.size>data_size_)return false;
            if(header.type==PERF_RECORD_LOST||header.type==PERF_RECORD_LOST_SAMPLES)return false;
            if(header.type==PERF_RECORD_FORK||header.type==PERF_RECORD_EXIT) {
                struct Record {perf_event_header header;uint32_t pid,ppid,tid,ptid;uint64_t time;} record{};
                if(header.size<sizeof(record))return false;
                copy(&record,tail_,sizeof(record));
                event(header.type==PERF_RECORD_FORK,record.tid,record.ptid,record.pid,record.time);
            }
            tail_+=header.size;
        }
        __atomic_store_n(&meta->data_tail,tail_,__ATOMIC_RELEASE);
        return true;
    }
};
