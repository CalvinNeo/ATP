#pragma once

#include <random>
#include <thread>
#include "../atp_impl.h"
#include "../udp_util.h"

ATP_PROC_RESULT normal_sendto(atp_callback_arguments * args);

static double loss_rate;
static size_t delay_time;

inline ATP_PROC_RESULT simulate_packet_loss_sendto(atp_callback_arguments * args){
    static std::default_random_engine e{get_current_ms()};
    static std::uniform_real_distribution<double> u{0, 1};
    double drop_rate_judge = u(e);
    if (drop_rate_judge < 0.5)
    {
        puts("simulated packet loss");
        return ATP_PROC_OK;
    }else{
        return normal_sendto(args);
    }
};

inline ATP_PROC_RESULT simulate_delayed_sendto(atp_callback_arguments * args){
    char * data = new char[args->length];
    std::memcpy(data, args->data, args->length);
    char * addr = new char[args->addr_len];
    std::memcpy(addr, args->addr, args->addr_len);

    atp_callback_arguments * new_arg = new atp_callback_arguments(*args);
    new_arg->data = data;
    new_arg->addr = (const SA *)addr;

    std::atomic_thread_fence(std::memory_order_seq_cst);
    std::thread send_thread{[=](){
        // printf("sleep at %llu\n", get_current_ms());
        std::this_thread::sleep_for(std::chrono::seconds(delay_time));
        // printf("wake and send at %llu\n", get_current_ms());
        normal_sendto(new_arg);
        delete [] data;
        delete [] addr;
        delete new_arg;
    }};
    std::atomic_thread_fence(std::memory_order_seq_cst);
    if (send_thread.joinable()) {
        send_thread.detach();
    }
    return ATP_PROC_OK;
};

struct FileObject{
    FILE* fp;
    size_t cache_size;
    char * cache;
    size_t current_p;
    size_t current_size;
    FileObject(int _fp, size_t _cache_size): fp(_fp), cache_size(_cache_size){
        cache = new char [cache_size];
        current_p = 0;
        current_size = 0;
    }
    ~FileObject(){
        delete [] cache;
    }
    char * get(size_t & n){
        if (current_p >= 0 && (current_p < current_size))
        {
            // There's unsend data in cache
            n = current_size - current_p;
            return cache + current_p;
        }else{
            // re-fill cache
            current_size = fread(cache, 1, cache_size, fp);
            current_p = 0;
            n = current_size;
            return cache;
        }
    }
    void ack_by_n(size_t n){
        current_p += n;
    }
    bool eof() const {
        return feof(fp) && !(current_p >= 0 && (current_p < current_size));
    }
};