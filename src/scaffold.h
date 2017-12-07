#pragma once

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <vector>
#include <chrono>
#include <map>
#include <cstdarg>

template <typename T>
struct SizableCircularBuffer {
    // This is the mask. Since it's always a power of 2, adding 1 to this value will return the size.
    size_t mask = 0;
    typedef std::pair<size_t, T> _Item;
    std::vector<_Item> elements;
    SizableCircularBuffer(){

    }
    SizableCircularBuffer(size_t origin_mask){
        size_t size = origin_mask + 1;
        if((size & (size - 1)) == 0){
            size = 1;
            do size *= 2; while (origin_mask >= size);
        }
        mask = size - 1;
        elements.resize(size);
    }
    T get(size_t i) const { 
        return elements[i & mask].second; 
    }
    void put(size_t i, T data) { 
        elements[i & mask] = std::make_pair(i, data);
    }

    void grow(size_t atleast_size){
        // Figure out the new size.
        // TODO make it effcient
        std::vector<_Item> old_elements = elements;
        size_t old_size = size();

        size_t new_size = mask + 1;
        do new_size *= 2; while (atleast_size >= new_size);
        elements.resize(new_size, _Item{});
        mask = new_size - 1;

        for(size_t i = 0; i < old_size; i++){
            printf("%d %d %d %d\n", mask, new_size, old_size, i);
            size_t & seq = old_elements[i].first;
            elements[seq & mask] = old_elements[i];
        }
    }
    void ensure_size(size_t atleast_size) { 
        if (atleast_size > size()) 
            grow(atleast_size); 
    }
    size_t size() const { 
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

