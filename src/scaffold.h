/*
*   Calvin Neo
*   Copyright (C) 2017  Calvin Neo <calvinneo@calvinneo.com>
*   https://github.com/CalvinNeo/ATP
*
*   This program is free software; you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation; either version 2 of the License, or
*   (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License along
*   with this program; if not, write to the Free Software Foundation, Inc.,
*   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#pragma once

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <vector>
#include <chrono>
#include <map>
#include <cstdarg>
#include <functional>
#include <climits>
#include <cassert>

template<typename T>
struct TPool{
    T * fetch(){
        if(cached.empty()){
            // If there is no cached items, request `gen()` to produce one
            return gen();
        }else{
            // Otherwise fetch directly from `cached`
            return cached.back();
            cached.pop_back();
        }
    }
    void release(T * x){
        cached.push_back(x);
    }
    TPool(std::function<T*()> generator) : gen(generator){

    }
    ~TPool(){
        for(T * x : cached){
            delete x;
            x = nullptr;
        }
    }
protected:
    std::vector<T *> cached;
    std::function<T*()> gen;
};

#define _ATP_LOG_TBUF
#ifdef _ATP_LOG_TBUF
#define _log_tbuf printf
#else
#define _log_tbuf(...)
#endif

template <typename T>
struct TBuffer{
    typedef int distance_t;

    distance_t distance(size_t index) const{
        // By default, `pivot` = `oldest_index`
        if (index < pivot)
        {
            return -(distance_t)(pivot - index);
        }else{
            return (distance_t)(index - pivot);
        }
    }
    distance_t get_pos(size_t index) const{
        distance_t dist = distance(index);
        assert(dist + capacity >= 0);
        size_t pos = (dist + capacity) % capacity;
        // The `pivot`th element is always at position `data[0]`
        return pos;
    }
    void init(){
        capacity = 1;
        data = new T*[capacity](nullptr);
        oldest_index = UINT_MAX;
        newest_index = 0;
    }
    T * front(){
        return at(oldest_index);
    }
    void pop_front(){
        size_t pos = get_pos(oldest_index);
        data[pos] = nullptr;
        oldest_index++;
        _log_tbuf("After pop front, Old index %u, new index %u, size %u\n", oldest_index, newest_index, size());
    }
    T * at(size_t index){
        size_t pos = get_pos(index);
        return data[pos];
    }
    void put(size_t index, T * item){
        size_t req = need_grow(index);
        if(empty()){
            oldest_index = newest_index = pivot = index;
            _log_tbuf("Set pivot to %u\n", pivot);
        }
        if(req > 0){
            grow(req);
        }
        size_t pos = get_pos(index);
        _log_tbuf("Distance between %u and pivot %u is %u. Capacity %u\n", index, pivot, distance(index), capacity);
        _log_tbuf("Calculated pos for index %u is %u. Pivot %u, Pointer at pos is %u\n", index, pos, pivot, data[pos]);

        assert(data[pos] == nullptr);
        data[pos] = item;

        if(index < oldest_index){
            oldest_index = index;
        }
        if(index > newest_index){
            newest_index = index;
        }
        _log_tbuf("After insert, Old index %u, new index %u, size %u\n", oldest_index, newest_index, size());

    }
    void clear(){
        // Don't help user deleting items
        delete [] data;
        data = nullptr;
    }
    size_t size() const{
        if (newest_index < oldest_index)
        {
            return 0;
        }
        return newest_index - oldest_index + 1;
    }
    bool empty() const{
        return size() == 0;
    }
    size_t next_pow_of_2(size_t n){
        n--;
        n |= n >> 1; n |= n >> 2;
        n |= n >> 4; n |= n >> 8; n |= n >> 16;
        n++;
        return n;
    }
    void grow(size_t ensured_size){
        size_t new_capacity = next_pow_of_2(ensured_size);
        _log_tbuf("Compute new capacity to be at least %u, actually %u \n", ensured_size, new_capacity);
        T ** newdata = new T*[new_capacity](nullptr);
        _log_tbuf("Re-locate elements from old index %u to new index %u \n", oldest_index, newest_index);
        for(size_t i = 0; i < size(); i++){
            size_t index = i + oldest_index;
            T * x = at(index);
            newdata[i] = x;
            _log_tbuf("Move [%u]-th element old[%u]=%u to new[%u]\n", index, get_pos(index), x, i);
        }
        capacity = new_capacity;
        delete [] data;
        data = newdata;
    }
    size_t need_grow(size_t index){
        if (empty())
        {
            return 1;
        }
        if(index <= oldest_index){
            // Previous
            if( (newest_index - index) >= capacity ){
                return newest_index - index + 1;
            }else{
                return 0;
            }
        }else{
            // Rear
            if( (index - oldest_index) >= capacity ){
                return index - oldest_index + 1;
            }else{
                return 0;
            }
        }
    }
    TBuffer(){
        init();
    }
    ~TBuffer(){
        clear();
    }
protected:
    size_t oldest_index = UINT_MAX, newest_index = 0, capacity = 0, pivot;
    T ** data = nullptr;
};


inline uint64_t get_current_ms(){
    using namespace std::chrono;
    time_point<system_clock, milliseconds> timepoint_now = time_point_cast<milliseconds>(system_clock::now());;
    auto tmp = duration_cast<milliseconds>(timepoint_now.time_since_epoch());  
    std::time_t timestamp = tmp.count();  
    return (uint64_t)timestamp;  
}
