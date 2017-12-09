#pragma once

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <vector>
#include <chrono>
#include <map>
#include <cstdarg>
#include <iostream>

template <typename T>
struct SizableCircularBuffer {
    // This is the mask. Since it's always a power of 2, adding 1 to this value will return the size.
    typedef std::pair<size_t, T> _Item;
    std::vector<_Item> elements;
    size_t oldest_index = 0;
    typedef _Item value_type;

    typename std::vector<_Item>::iterator begin() { return elements.begin(); }
    typename std::vector<_Item>::iterator end() { return elements.end(); }
    typename std::vector<_Item>::const_iterator begin() const { return elements.begin(); }
    typename std::vector<_Item>::const_iterator end() const  { return elements.end(); }

    SizableCircularBuffer(){

    }
    SizableCircularBuffer(size_t origin_size){
        if((origin_size & (origin_size - 1)) != 0){
            size_t size = 1;
            do size *= 2; while (origin_size > size);
            origin_size = size;
        }
        elements.resize(origin_size);
    }
    T get(size_t i) const { 
        return elements[i % size()].second; 
    }
    void put(size_t i, T data) { 
        
    }
    void raw_put(size_t i, T data){
        elements[i % size()] = std::make_pair(i, data);
    }
    void grow(size_t atleast_size){
        // Figure out the new size.
        // TODO make it effcient
        std::vector<_Item> old_elements = elements;
        size_t old_size = size();

        size_t new_size = old_size;
        do new_size *= 2; while (atleast_size >= new_size);
        elements.resize(new_size, _Item{});

        for(size_t i = 0; i < old_size; i++){
            size_t seq = old_elements[i].first;
            elements[seq % size()] = old_elements[i];
        }
    }
    void ensure_size(size_t atleast_size) { 
        if (atleast_size > size()) 
            grow(atleast_size); 
    }
    size_t size() const { 
        return elements.size(); 
    }
};


inline uint64_t get_current_ms(){
    using namespace std::chrono;
    time_point<system_clock, milliseconds> timepoint_now = time_point_cast<milliseconds>(system_clock::now());;
    auto tmp = duration_cast<milliseconds>(timepoint_now.time_since_epoch());  
    std::time_t timestamp = tmp.count();  
    return (uint64_t)timestamp;  
}

