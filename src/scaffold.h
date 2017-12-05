#pragma once

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <vector>
#include <chrono>

template <typename T>
struct SizableCircularBuffer {
    // This is the mask. Since it's always a power of 2, adding 1 to this value will return the size.
    size_t mask;
    std::vector<T> elements;
    SizableCircularBuffer(){

    }
    SizableCircularBuffer(size_t origin_mask){
        size_t size = origin_mask + 1;
        if((size & (size - 1)) == 0){
            size = 1;
            do size *= 2; while (origin_mask >= size);
        }
        mask = size - 1;
        grow(size);
    }
    T get(size_t i) const { 
        return elements[i & mask]; 
    }
    void put(size_t i, T data) { 
        elements[i & mask] = data;
    }

    void grow(size_t index){
        // Figure out the new size.
        size_t size = mask + 1;
        do size *= 2; while (index >= size);

        elements.resize(size, T{});

        // Swap to the newly allocated buffer
        mask = size - 1;
    }
    void ensure_size(size_t index) { 
        if (index > mask) 
            grow(index); 
    }
    size_t size() { 
        return mask + 1; 
    }
};


inline uint64_t get_current_ms(){
    using namespace std::chrono;
    time_point<system_clock,milliseconds> timepoint_now = time_point_cast<milliseconds>(system_clock::now());;
    auto tmp = duration_cast<milliseconds>(timepoint_now.time_since_epoch());  
    std::time_t timestamp = tmp.count();  
    return (uint64_t)timestamp;  
}
